use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bip39::Mnemonic;
use bitcoin::{secp256k1, Network, OutPoint};
use fedimint_core::runtime::spawn;
use fedimint_core::task::TaskGroup;
use fedimint_core::Amount;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning::ln::PaymentHash;
use ldk_node::lightning_invoice::Bolt11Invoice;
use ldk_node::payment::{PaymentKind, PaymentStatus};
use lightning::ln::PaymentPreimage;
use lightning::util::scid_utils::scid_from_parts;
use tokio::sync::mpsc::Sender;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::{error, info};

use super::{ChannelInfo, ILnRpcClient, LightningRpcError, RouteHtlcStream};
use crate::gateway_lnrpc::create_invoice_request::Description;
use crate::gateway_lnrpc::intercept_htlc_response::{Action, Settle};
use crate::gateway_lnrpc::{
    CloseChannelsWithPeerResponse, CreateInvoiceRequest, CreateInvoiceResponse, EmptyResponse,
    GetBalancesResponse, GetLnOnchainAddressResponse, GetNodeInfoResponse, GetRouteHintsResponse,
    InterceptHtlcRequest, InterceptHtlcResponse, PayInvoiceResponse,
};

pub struct GatewayLdkClient {
    /// The underlying lightning node.
    node: Arc<ldk_node::Node>,

    /// The client for querying data about the blockchain.
    esplora_client: esplora_client::AsyncClient,

    /// A handle to the task that processes incoming events from the lightning
    /// node. Responsible for sending incoming HTLCs to the caller of
    /// `route_htlcs`.
    /// TODO: This should be a shutdown sender instead, and we can discard the
    /// handle.
    event_handler_task_handle: tokio::task::JoinHandle<()>,

    /// The HTLC stream, until it is taken by calling
    /// `ILnRpcClient::route_htlcs`.
    htlc_stream_receiver_or:
        Option<tokio::sync::mpsc::Receiver<Result<InterceptHtlcRequest, Status>>>,
}

impl std::fmt::Debug for GatewayLdkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayLdkClient").finish_non_exhaustive()
    }
}

impl GatewayLdkClient {
    /// Creates a new `GatewayLdkClient` instance and starts the underlying
    /// lightning node. All resources, including the lightning node, will be
    /// cleaned up when the returned `GatewayLdkClient` instance is dropped.
    /// There's no need to manually stop the node.
    pub fn new(
        data_dir: &Path,
        esplora_server_url: &str,
        network: Network,
        lightning_port: u16,
        mnemonic: Mnemonic,
    ) -> anyhow::Result<Self> {
        let mut node_builder = ldk_node::Builder::from_config(ldk_node::Config {
            network,
            listening_addresses: Some(vec![SocketAddress::TcpIpV4 {
                addr: [0, 0, 0, 0],
                port: lightning_port,
            }]),
            onchain_wallet_sync_interval_secs: 10,
            wallet_sync_interval_secs: 10,
            ..Default::default()
        });
        node_builder.set_entropy_bip39_mnemonic(mnemonic, None);
        node_builder
            .set_esplora_server(esplora_server_url.to_string())
            .set_gossip_source_p2p();
        let Some(data_dir_str) = data_dir.to_str() else {
            return Err(anyhow::anyhow!("Invalid data dir path"));
        };
        node_builder.set_storage_dir_path(data_dir_str.to_string());

        let node = Arc::new(node_builder.build()?);
        node.start().map_err(|e| {
            error!(?e, "Failed to start LDK Node");
            LightningRpcError::FailedToConnect
        })?;

        let (htlc_stream_sender, htlc_stream_receiver) = tokio::sync::mpsc::channel(1024);

        let node_clone = node.clone();
        let event_handler_task_handle = spawn("ldk lightning node event handler", async move {
            loop {
                Self::handle_next_event(&node_clone, &htlc_stream_sender).await;
            }
        });

        Ok(GatewayLdkClient {
            node,
            esplora_client: esplora_client::Builder::new(esplora_server_url).build_async()?,
            event_handler_task_handle,
            htlc_stream_receiver_or: Some(htlc_stream_receiver),
        })
    }

    async fn handle_next_event(
        node: &ldk_node::Node,
        htlc_stream_sender: &Sender<Result<InterceptHtlcRequest, Status>>,
    ) {
        if let ldk_node::Event::PaymentClaimable {
            payment_id: _,
            payment_hash,
            claimable_amount_msat,
            claim_deadline,
        } = node.next_event_async().await
        {
            if let Err(e) = htlc_stream_sender
                .send(Ok(InterceptHtlcRequest {
                    payment_hash: payment_hash.0.to_vec(),
                    incoming_amount_msat: claimable_amount_msat,
                    outgoing_amount_msat: 0,
                    incoming_expiry: claim_deadline.unwrap_or_default(),
                    short_channel_id: None,
                    incoming_chan_id: 0,
                    htlc_id: 0,
                }))
                .await
            {
                error!(?e, "Failed send InterceptHtlcRequest to stream");
            }
        }

        // The `PaymentClaimable` event is the only event type that we are interested
        // in. We can safely ignore all other events.
        node.event_handled();
    }

    /// Converts a transaction outpoint to a short channel ID by querying the
    /// blockchain.
    async fn outpoint_to_scid(&self, funding_txo: OutPoint) -> anyhow::Result<u64> {
        let block_height = self
            .esplora_client
            .get_merkle_proof(&funding_txo.txid)
            .await?
            .ok_or(anyhow::anyhow!("Failed to get merkle proof"))?
            .block_height;

        let block_hash = self.esplora_client.get_block_hash(block_height).await?;

        let block = self
            .esplora_client
            .get_block_by_hash(&block_hash)
            .await?
            .ok_or(anyhow::anyhow!("Failed to get block"))?;

        let tx_index = block
            .txdata
            .iter()
            .enumerate()
            .find(|(_, tx)| tx.txid() == funding_txo.txid)
            .ok_or(anyhow::anyhow!("Failed to find transaction"))?
            .0 as u32;

        let output_index = funding_txo.vout;

        scid_from_parts(
            u64::from(block_height),
            u64::from(tx_index),
            u64::from(output_index),
        )
        .map_err(|e| anyhow::anyhow!("Failed to convert to short channel ID: {e:?}"))
    }
}

impl Drop for GatewayLdkClient {
    fn drop(&mut self) {
        self.event_handler_task_handle.abort();

        info!("Stopping LDK Node...");
        if let Err(e) = self.node.stop() {
            error!(?e, "Failed to stop LDK Node");
        } else {
            info!("LDK Node stopped.");
        }
    }
}

#[async_trait]
impl ILnRpcClient for GatewayLdkClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        let node_status = self.node.status();

        let Some(chain_tip_block_summary) = self
            .esplora_client
            .get_blocks(None)
            .await
            .map_err(|e| LightningRpcError::FailedToGetNodeInfo {
                failure_reason: format!("Failed get chain tip block summary: {e:?}"),
            })?
            .into_iter()
            .next()
        else {
            return Err(LightningRpcError::FailedToGetNodeInfo {
                failure_reason:
                    "Failed to get chain tip block summary (empty block list was returned)"
                        .to_string(),
            });
        };

        let esplora_chain_tip_timestamp = chain_tip_block_summary.time.timestamp;
        let block_height: u32 = chain_tip_block_summary.time.height;

        let synced_to_chain = node_status.latest_wallet_sync_timestamp.unwrap_or_default()
            > esplora_chain_tip_timestamp
            && node_status
                .latest_onchain_wallet_sync_timestamp
                .unwrap_or_default()
                > esplora_chain_tip_timestamp;

        Ok(GetNodeInfoResponse {
            pub_key: self.node.node_id().serialize().to_vec(),
            // TODO: This is a placeholder. We need to get the actual alias from the LDK node.
            alias: format!("LDK Fedimint Gateway Node {}", self.node.node_id()),
            network: self.node.config().network.to_string(),
            block_height,
            synced_to_chain,
        })
    }

    async fn routehints(
        &self,
        _num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        // TODO: Return real route hints. Not strictly necessary but would be nice to
        // have.
        Ok(GetRouteHintsResponse {
            route_hints: vec![],
        })
    }

    // TODO: Respect `max_delay` and `max_fee` parameters.
    async fn pay(
        &self,
        invoice: Bolt11Invoice,
        _max_delay: u64,
        _max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let payment_id = match self.node.bolt11_payment().send(&invoice) {
            Ok(payment_id) => payment_id,
            Err(e) => {
                return Err(LightningRpcError::FailedPayment {
                    failure_reason: format!("LDK payment failed to initialize: {e:?}"),
                });
            }
        };

        // TODO: Find a way to avoid looping/polling to know when a payment is
        // completed. `ldk-node` provides `PaymentSuccessful` and `PaymentFailed`
        // events, but interacting with the node event queue here isn't
        // straightforward.
        loop {
            if let Some(payment_details) = self.node.payment(&payment_id) {
                match payment_details.status {
                    PaymentStatus::Pending => {}
                    PaymentStatus::Succeeded => {
                        if let PaymentKind::Bolt11 {
                            preimage: Some(preimage),
                            ..
                        } = payment_details.kind
                        {
                            return Ok(PayInvoiceResponse {
                                preimage: preimage.0.to_vec(),
                            });
                        }
                    }
                    PaymentStatus::Failed => {
                        return Err(LightningRpcError::FailedPayment {
                            failure_reason: "LDK payment failed".to_string(),
                        });
                    }
                }
            }
            fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn route_htlcs<'a>(
        mut self: Box<Self>,
        _task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        let route_htlc_stream = match self.htlc_stream_receiver_or.take() {
            Some(stream) => Ok(Box::pin(ReceiverStream::new(stream))),
            None => Err(LightningRpcError::FailedToRouteHtlcs {
                failure_reason:
                    "Stream does not exist. Likely was already taken by calling `route_htlcs()`."
                        .to_string(),
            }),
        }?;

        Ok((route_htlc_stream, Arc::new(*self)))
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        let InterceptHtlcResponse {
            action,
            payment_hash,
            incoming_chan_id: _,
            htlc_id: _,
        } = htlc;

        let ph = PaymentHash(payment_hash.clone().try_into().map_err(|_| {
            LightningRpcError::FailedToCompleteHtlc {
                failure_reason: "Failed to parse payment hash".to_string(),
            }
        })?);

        // TODO: Get the actual amount from the LDK node. Probably makes the
        // most sense to pipe it through the `InterceptHtlcResponse` struct.
        // This value is only used by `ldk-node` to ensure that the amount
        // claimed isn't less than the amount expected, but we've already
        // verified that the amount is correct when we intercepted the payment.
        let claimable_amount_msat = 999_999_999_999_999;

        let ph_hex_str = hex::encode(payment_hash);

        if let Some(Action::Settle(Settle { preimage })) = action {
            self.node
                .bolt11_payment()
                .claim_for_hash(
                    ph,
                    claimable_amount_msat,
                    PaymentPreimage(preimage.try_into().unwrap()),
                )
                .map_err(|_| LightningRpcError::FailedToCompleteHtlc {
                    failure_reason: format!("Failed to claim LDK payment with hash {ph_hex_str}"),
                })?;
        } else {
            error!("Unwinding payment with hash {ph_hex_str} because the action was not `Settle`");
            self.node.bolt11_payment().fail_for_hash(ph).map_err(|_| {
                LightningRpcError::FailedToCompleteHtlc {
                    failure_reason: format!("Failed to unwind LDK payment with hash {ph_hex_str}"),
                }
            })?;
        };

        return Ok(EmptyResponse {});
    }

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        let payment_hash_or = if create_invoice_request.payment_hash.is_empty() {
            None
        } else {
            Some(PaymentHash(create_invoice_request.payment_hash.try_into().map_err(
                |_| LightningRpcError::FailedToGetInvoice {
                    failure_reason: "Failed to convert Vec<u8> to [u8; 32] (this probably means that LDK received an invalid payment hash)".to_string(),
                },
            )?))
        };

        // Currently `ldk-node` only supports direct descriptions.
        // See https://github.com/lightningdevkit/ldk-node/issues/325.
        // TODO: Once the above issue is resolved, we should support
        // description hashes as well.
        let Some(Description::Direct(description_str)) = &create_invoice_request.description else {
            return Err(LightningRpcError::FailedToGetInvoice {
                failure_reason:
                    "Only direct descriptions are supported for LDK gateways at this time"
                        .to_string(),
            });
        };

        let invoice = match payment_hash_or {
            Some(payment_hash) => self.node.bolt11_payment().receive_for_hash(
                create_invoice_request.amount_msat,
                description_str,
                create_invoice_request.expiry_secs,
                payment_hash,
            ),
            None => self.node.bolt11_payment().receive(
                create_invoice_request.amount_msat,
                description_str,
                create_invoice_request.expiry_secs,
            ),
        }
        .map_err(|e| LightningRpcError::FailedToGetInvoice {
            failure_reason: e.to_string(),
        })?;

        Ok(CreateInvoiceResponse {
            invoice: invoice.to_string(),
        })
    }

    async fn get_ln_onchain_address(
        &self,
    ) -> Result<GetLnOnchainAddressResponse, LightningRpcError> {
        self.node
            .onchain_payment()
            .new_address()
            .map(|address| GetLnOnchainAddressResponse {
                address: address.to_string(),
            })
            .map_err(|e| LightningRpcError::FailedToGetLnOnchainAddress {
                failure_reason: e.to_string(),
            })
    }

    async fn open_channel(
        &self,
        pubkey: secp256k1::PublicKey,
        host: String,
        channel_size_sats: u64,
        push_amount_sats: u64,
    ) -> Result<EmptyResponse, LightningRpcError> {
        let push_amount_msats_or = if push_amount_sats == 0 {
            None
        } else {
            Some(push_amount_sats * 1000)
        };

        self.node
            .connect_open_channel(
                pubkey,
                SocketAddress::from_str(&host).map_err(|e| {
                    LightningRpcError::FailedToConnectToPeer {
                        failure_reason: e.to_string(),
                    }
                })?,
                channel_size_sats,
                push_amount_msats_or,
                None,
                true,
            )
            .map_err(|e| LightningRpcError::FailedToOpenChannel {
                failure_reason: e.to_string(),
            })?;

        Ok(EmptyResponse {})
    }

    async fn close_channels_with_peer(
        &self,
        pubkey: secp256k1::PublicKey,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError> {
        let mut num_channels_closed = 0;

        for channel_with_peer in self
            .node
            .list_channels()
            .iter()
            .filter(|channel| channel.counterparty_node_id == pubkey)
        {
            if self
                .node
                .close_channel(&channel_with_peer.user_channel_id, pubkey)
                .is_ok()
            {
                num_channels_closed += 1;
            }
        }

        Ok(CloseChannelsWithPeerResponse {
            num_channels_closed,
        })
    }

    async fn list_active_channels(&self) -> Result<Vec<ChannelInfo>, LightningRpcError> {
        let mut channels = Vec::new();

        for channel_details in self
            .node
            .list_channels()
            .iter()
            .filter(|channel| channel.is_channel_ready)
        {
            channels.push(ChannelInfo {
                remote_pubkey: channel_details.counterparty_node_id,
                channel_size_sats: channel_details.channel_value_sats,
                outbound_liquidity_sats: channel_details.outbound_capacity_msat / 1000,
                inbound_liquidity_sats: channel_details.inbound_capacity_msat / 1000,
                short_channel_id: match channel_details.funding_txo {
                    Some(funding_txo) => self.outpoint_to_scid(funding_txo).await.unwrap_or(0),
                    None => 0,
                },
            });
        }

        Ok(channels)
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        let balances = self.node.list_balances();
        Ok(GetBalancesResponse {
            onchain_balance_sats: balances.total_onchain_balance_sats,
            lightning_balance_msats: balances.total_lightning_balance_sats * 1000,
        })
    }
}
