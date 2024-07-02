use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::{secp256k1, Network, OutPoint};
use fedimint_core::runtime::spawn;
use fedimint_core::task::TaskGroup;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning::ln::PaymentHash;
use ldk_node::lightning_invoice::Bolt11Invoice;
use ldk_node::payment::{PaymentKind, PaymentStatus};
use lightning::ln::PaymentPreimage;
use tokio::sync::mpsc::Sender;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::{error, info};

use super::cln::RouteHtlcStream;
use super::{ChannelInfo, ILnRpcClient, LightningRpcError};
use crate::gateway_lnrpc::create_invoice_request::Description;
use crate::gateway_lnrpc::intercept_htlc_response::{Action, Settle};
use crate::gateway_lnrpc::{
    CloseChannelsWithPeerResponse, CreateInvoiceRequest, CreateInvoiceResponse, EmptyResponse,
    GetFundingAddressResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcRequest,
    InterceptHtlcResponse, PayInvoiceRequest, PayInvoiceResponse,
};

pub struct GatewayLdkClient {
    /// The underlying lightning node.
    node: Arc<ldk_node::Node>,

    /// The client for querying data about the blockchain.
    esplora_client: esplora_client::AsyncClient,

    /// A handle to the task that seeds the HTLC stream.
    /// TODO: This should be a shutdown sender instead, and we can discard the
    /// handle.
    htlc_stream_seeder_task_handle: tokio::task::JoinHandle<()>,

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
        node_builder
            .set_esplora_server(esplora_server_url.to_string())
            .set_gossip_source_p2p();
        let Some(data_dir_str) = data_dir.to_str() else {
            return Err(anyhow::anyhow!("Invalid data dir path"));
        };
        node_builder.set_storage_dir_path(data_dir_str.to_string());

        let node = Arc::new(node_builder.build()?);
        node.start().map_err(|e| {
            error!("Failed to start LDK Node: {e:?}");
            LightningRpcError::FailedToConnect
        })?;

        let (htlc_stream_sender, htlc_stream_receiver) = tokio::sync::mpsc::channel(1024);

        let node_clone = node.clone();
        let htlc_stream_seeder_task_handle = spawn(
            "ldk lightning node incoming htlc stream seeder",
            async move {
                loop {
                    if let Err(e) =
                        Self::seed_route_htlcs_stream(&node_clone, &htlc_stream_sender).await
                    {
                        error!("Failed to seed route htlcs stream: {e:?}");
                        break;
                    }
                }
            },
        );

        Ok(GatewayLdkClient {
            node,
            esplora_client: esplora_client::Builder::new(esplora_server_url).build_async()?,
            htlc_stream_seeder_task_handle,
            htlc_stream_receiver_or: Some(htlc_stream_receiver),
        })
    }

    async fn seed_route_htlcs_stream(
        node: &ldk_node::Node,
        htlc_stream_sender: &Sender<Result<InterceptHtlcRequest, Status>>,
    ) -> anyhow::Result<()> {
        if let ldk_node::Event::PaymentClaimable {
            payment_id: _,
            payment_hash,
            claimable_amount_msat,
            claim_deadline,
        } = node.next_event_async().await
        {
            htlc_stream_sender
                .send(Ok(InterceptHtlcRequest {
                    payment_hash: payment_hash.0.to_vec(),
                    incoming_amount_msat: claimable_amount_msat,
                    outgoing_amount_msat: 0,
                    incoming_expiry: claim_deadline.unwrap_or_default(),
                    short_channel_id: None,
                    incoming_chan_id: 0,
                    htlc_id: 0,
                }))
                .await?;
        }

        // The `PaymentClaimable` event is the only event type that we are interested
        // in. We can safely ignore all other events.
        node.event_handled();

        Ok(())
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

        Ok(create_short_channel_id(
            block_height,
            tx_index,
            output_index,
        ))
    }
}

impl Drop for GatewayLdkClient {
    fn drop(&mut self) {
        self.htlc_stream_seeder_task_handle.abort();

        info!("Stopping LDK Node...");
        if let Err(err) = self.node.stop() {
            error!("Failed to stop LDK Node: {err:?}");
        } else {
            info!("LDK Node stopped.");
        }
    }
}

#[async_trait]
impl ILnRpcClient for GatewayLdkClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        let node_status = self.node.status();

        let chain_tip_block_summary = self
            .esplora_client
            .get_blocks(None)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

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
            alias: "LDK Fedimint Gateway Node".to_string(),
            network: match self.node.config().network {
                Network::Bitcoin => "main",
                Network::Testnet => "test",
                Network::Signet => "signet",
                Network::Regtest => "regtest",
                _ => panic!("Unsupported network"),
            }
            .to_string(),
            block_height,
            synced_to_chain,
        })
    }

    async fn routehints(
        &self,
        _num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        Ok(GetRouteHintsResponse {
            route_hints: vec![],
        })
    }

    async fn pay(
        &self,
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let parsed_invoice: Bolt11Invoice =
            Bolt11Invoice::from_str(&invoice.invoice).map_err(|e| {
                LightningRpcError::FailedPayment {
                    failure_reason: format!("Failed to parse invoice: {e:?}"),
                }
            })?;

        let payment_id = match self.node.bolt11_payment().send(&parsed_invoice) {
            Ok(payment_id) => payment_id,
            Err(e) => {
                return Err(LightningRpcError::FailedPayment {
                    failure_reason: format!("LDK payment failed to initialize: {e:?}"),
                });
            }
        };

        // TODO: Find a way to avoid looping/polling to find out when a payment is
        // completed. `ldk-node` provides `PaymentSuccessful` and `PaymentFailed`
        // events, but routing them to specific payment IDs isn't straightforward.
        tokio::time::timeout(Duration::from_secs(30), async {
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
        })
        .await
        .map_err(|_| LightningRpcError::FailedPayment {
            failure_reason: "LDK payment timed out".to_string(),
        })?
    }

    async fn route_htlcs<'a>(
        mut self: Box<Self>,
        _task_group: &mut TaskGroup,
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

        let ph = PaymentHash(payment_hash.clone().try_into().unwrap());

        // TODO: Get the actual amount from the LDK node. Probably makes the
        // most sense to pipe it through the `InterceptHtlcResponse` struct.
        // This value is only used by `ldk-node` to ensure that the amount
        // claimed isn't less than the amount expected, but we've already
        // verified that the amount is correct when we intercepted the HTLC.
        let claimable_amount_msat = 999_999_999_999_999;

        let ph_hex_str = hex::encode(payment_hash);

        match action {
            Some(Action::Settle(Settle { preimage })) => {
                self.node
                    .bolt11_payment()
                    .claim_for_hash(
                        ph,
                        claimable_amount_msat,
                        PaymentPreimage(preimage.try_into().unwrap()),
                    )
                    .map_err(|_| LightningRpcError::FailedToCompleteHtlc {
                        failure_reason: format!(
                            "Failed to claim LDK payment with hash {ph_hex_str}"
                        ),
                    })?;
            }
            _ => {
                self.node.bolt11_payment().fail_for_hash(ph).map_err(|_| {
                    LightningRpcError::FailedToCompleteHtlc {
                        failure_reason: format!(
                            "Failed to unwind LDK payment with hash {ph_hex_str}"
                        ),
                    }
                })?;
            }
        };

        return Ok(EmptyResponse {});
    }

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        let payment_hash = PaymentHash(create_invoice_request.payment_hash.try_into().map_err(
            |_| LightningRpcError::FailedToGetInvoice {
                failure_reason: "Failed to convert Vec<u8> to [u8; 32] (this probably means that LDK received an invalid payment hash)".to_string(),
            },
        )?);

        let invoice = self
            .node
            .bolt11_payment()
            .receive_for_hash(
                create_invoice_request.amount_msat,
                if let Some(Description::Direct(description)) = &create_invoice_request.description
                {
                    description
                } else {
                    ""
                },
                create_invoice_request.expiry_secs,
                payment_hash,
            )
            .map_err(|e| LightningRpcError::FailedToGetInvoice {
                failure_reason: e.to_string(),
            })?;

        Ok(CreateInvoiceResponse {
            invoice: invoice.to_string(),
        })
    }

    async fn get_funding_address(&self) -> Result<GetFundingAddressResponse, LightningRpcError> {
        self.node
            .onchain_payment()
            .new_address()
            .map(|address| GetFundingAddressResponse {
                address: address.to_string(),
            })
            .map_err(|e| LightningRpcError::FailedToGetFundingAddress {
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
                remote_pubkey: channel_details.counterparty_node_id.to_string(),
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
}

fn create_short_channel_id(block_height: u32, transaction_index: u32, output_index: u32) -> u64 {
    let block_height = u64::from(block_height) << 40; // Shift left by 40 bits
    let transaction_index = u64::from(transaction_index) << 16; // Shift left by 16 bits
    let output_index = u64::from(output_index); // No shift needed for the last 16 bits

    block_height | transaction_index | output_index
}
