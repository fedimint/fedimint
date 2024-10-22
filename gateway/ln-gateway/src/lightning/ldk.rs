use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::{secp256k1, Address, Network, OutPoint};
use fedimint_bip39::Mnemonic;
use fedimint_core::bitcoin_migration::{
    bitcoin30_to_bitcoin32_address, bitcoin30_to_bitcoin32_invoice, bitcoin30_to_bitcoin32_network,
    bitcoin30_to_bitcoin32_payment_preimage, bitcoin30_to_bitcoin32_secp256k1_pubkey,
    bitcoin32_to_bitcoin30_outpoint, bitcoin32_to_bitcoin30_secp256k1_pubkey,
};
use fedimint_core::runtime::spawn;
use fedimint_core::task::TaskGroup;
use fedimint_core::{Amount, BitcoinAmountOrAll};
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning::ln::PaymentHash;
use ldk_node::lightning::routing::gossip::NodeAlias;
use ldk_node::payment::{PaymentKind, PaymentStatus, SendingParameters};
use lightning::ln::PaymentPreimage;
use lightning::util::scid_utils::scid_from_parts;
use lightning_invoice::Bolt11Invoice;
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
    InterceptHtlcRequest, InterceptHtlcResponse, OpenChannelResponse, PayInvoiceResponse,
    WithdrawOnchainResponse,
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
        // In devimint, gateways must allow for other gateways to open channels to them.
        // To ensure this works, we must set a node alias to signal to ldk-node that we
        // should accept incoming public channels. However, on mainnet we can disable
        // this for better privacy.
        let node_alias = if network == Network::Bitcoin {
            None
        } else {
            let alias = format!("{network} LDK Gateway");
            let mut bytes = [0u8; 32];
            bytes[..alias.as_bytes().len()].copy_from_slice(alias.as_bytes());
            Some(NodeAlias(bytes))
        };

        let mut node_builder = ldk_node::Builder::from_config(ldk_node::config::Config {
            network: bitcoin30_to_bitcoin32_network(&network),
            listening_addresses: Some(vec![SocketAddress::TcpIpV4 {
                addr: [0, 0, 0, 0],
                port: lightning_port,
            }]),
            node_alias,
            ..Default::default()
        });
        node_builder
            .set_entropy_bip39_mnemonic(mnemonic, None)
            .set_chain_source_esplora(esplora_server_url.to_string(), None);
        let Some(data_dir_str) = data_dir.to_str() else {
            return Err(anyhow::anyhow!("Invalid data dir path"));
        };
        node_builder.set_storage_dir_path(data_dir_str.to_string());

        let node = Arc::new(node_builder.build()?);
        // TODO: Call `start_with_runtime()` instead of `start()`.
        // See https://github.com/fedimint/fedimint/issues/6159
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
        Ok(GetNodeInfoResponse {
            pub_key: self.node.node_id().serialize().to_vec(),
            alias: match self.node.node_alias() {
                Some(alias) => alias.to_string(),
                None => format!("LDK Fedimint Gateway Node {}", self.node.node_id()),
            },
            network: self.node.config().network.to_string(),
            block_height: node_status.current_best_block.height,
            synced_to_chain: node_status.is_running && node_status.is_listening,
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

    async fn pay(
        &self,
        invoice: Bolt11Invoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let payment_id = match self.node.bolt11_payment().send(
            &bitcoin30_to_bitcoin32_invoice(&invoice),
            Some(SendingParameters {
                max_total_routing_fee_msat: Some(Some(max_fee.msats)),
                max_total_cltv_expiry_delta: Some(max_delay as u32),
                max_path_count: None,
                max_channel_saturation_power_of_half: None,
            }),
        ) {
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
                    bitcoin30_to_bitcoin32_payment_preimage(&PaymentPreimage(
                        preimage.try_into().unwrap(),
                    )),
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
        let description_str = match create_invoice_request.description {
            Some(Description::Direct(desc)) => desc,
            _ => String::new(),
        };

        let invoice = match payment_hash_or {
            Some(payment_hash) => self.node.bolt11_payment().receive_for_hash(
                create_invoice_request.amount_msat,
                description_str.as_str(),
                create_invoice_request.expiry_secs,
                payment_hash,
            ),
            None => self.node.bolt11_payment().receive(
                create_invoice_request.amount_msat,
                description_str.as_str(),
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

    async fn withdraw_onchain(
        &self,
        address: Address,
        amount: BitcoinAmountOrAll,
        // TODO: Respect this fee rate once `ldk-node` supports setting a custom fee rate.
        // This work is planned to be in `ldk-node` v0.4 and is tracked here:
        // https://github.com/lightningdevkit/ldk-node/issues/176
        _fee_rate_sats_per_vbyte: u64,
    ) -> Result<WithdrawOnchainResponse, LightningRpcError> {
        let onchain = self.node.onchain_payment();

        let txid = match amount {
            BitcoinAmountOrAll::All => {
                onchain.send_all_to_address(&bitcoin30_to_bitcoin32_address(&address))
            }
            BitcoinAmountOrAll::Amount(amount_sats) => onchain.send_to_address(
                &bitcoin30_to_bitcoin32_address(&address),
                amount_sats.to_sat(),
            ),
        }
        .map_err(|e| LightningRpcError::FailedToWithdrawOnchain {
            failure_reason: e.to_string(),
        })?;

        Ok(WithdrawOnchainResponse {
            txid: txid.to_string(),
        })
    }

    async fn open_channel(
        &self,
        pubkey: secp256k1::PublicKey,
        host: String,
        channel_size_sats: u64,
        push_amount_sats: u64,
    ) -> Result<OpenChannelResponse, LightningRpcError> {
        let funding_txid_or = self
            .node
            .list_channels()
            .iter()
            .find(|channel| {
                channel.counterparty_node_id == bitcoin30_to_bitcoin32_secp256k1_pubkey(&pubkey)
            })
            .and_then(|channel| channel.funding_txo)
            .map(|funding_txo| funding_txo.txid);

        if let Some(funding_txid) = funding_txid_or {
            return Ok(OpenChannelResponse {
                funding_txid: funding_txid.to_string(),
            });
        }

        let push_amount_msats_or = if push_amount_sats == 0 {
            None
        } else {
            Some(push_amount_sats * 1000)
        };

        let user_channel_id = self
            .node
            .open_announced_channel(
                bitcoin30_to_bitcoin32_secp256k1_pubkey(&pubkey),
                SocketAddress::from_str(&host).map_err(|e| {
                    LightningRpcError::FailedToConnectToPeer {
                        failure_reason: e.to_string(),
                    }
                })?,
                channel_size_sats,
                push_amount_msats_or,
                None,
            )
            .map_err(|e| LightningRpcError::FailedToOpenChannel {
                failure_reason: e.to_string(),
            })?;

        // The channel isn't always visible immediately, so we need to poll for it.
        for _ in 0..10 {
            let funding_txid_or = self
                .node
                .list_channels()
                .iter()
                .find(|channel| channel.user_channel_id == user_channel_id)
                .and_then(|channel| channel.funding_txo)
                .map(|funding_txo| funding_txo.txid);

            if let Some(funding_txid) = funding_txid_or {
                return Ok(OpenChannelResponse {
                    funding_txid: funding_txid.to_string(),
                });
            }

            fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
        }

        Err(LightningRpcError::FailedToOpenChannel {
            failure_reason: "Channel could not be opened".to_string(),
        })
    }

    async fn close_channels_with_peer(
        &self,
        pubkey: secp256k1::PublicKey,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError> {
        let mut num_channels_closed = 0;

        for channel_with_peer in self.node.list_channels().iter().filter(|channel| {
            channel.counterparty_node_id == bitcoin30_to_bitcoin32_secp256k1_pubkey(&pubkey)
        }) {
            if self
                .node
                .close_channel(
                    &channel_with_peer.user_channel_id,
                    bitcoin30_to_bitcoin32_secp256k1_pubkey(&pubkey),
                )
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
                remote_pubkey: bitcoin32_to_bitcoin30_secp256k1_pubkey(
                    &channel_details.counterparty_node_id,
                ),
                channel_size_sats: channel_details.channel_value_sats,
                outbound_liquidity_sats: channel_details.outbound_capacity_msat / 1000,
                inbound_liquidity_sats: channel_details.inbound_capacity_msat / 1000,
                short_channel_id: match channel_details.funding_txo {
                    Some(funding_txo) => self
                        .outpoint_to_scid(bitcoin32_to_bitcoin30_outpoint(&funding_txo))
                        .await
                        .unwrap_or(0),
                    None => 0,
                },
            });
        }

        Ok(channels)
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        let balances = self.node.list_balances();
        let channel_lists = self.node.list_channels();
        // map and get the total inbound_capacity_msat in the channels
        let total_inbound_liquidity_balance_msat: u64 = channel_lists
            .iter()
            .map(|channel| channel.inbound_capacity_msat)
            .sum();

        Ok(GetBalancesResponse {
            onchain_balance_sats: balances.total_onchain_balance_sats,
            lightning_balance_msats: balances.total_lightning_balance_sats * 1000,
            inbound_lightning_liquidity_msats: total_inbound_liquidity_balance_msat,
        })
    }

    async fn sync_to_chain(&self, block_height: u32) -> Result<EmptyResponse, LightningRpcError> {
        loop {
            self.node
                .sync_wallets()
                .map_err(|e| LightningRpcError::FailedToSyncToChain {
                    failure_reason: e.to_string(),
                })?;

            if self.node.status().current_best_block.height < block_height {
                fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
            } else {
                break;
            }
        }

        Ok(EmptyResponse {})
    }
}
