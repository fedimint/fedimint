use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::{FeeRate, Network, OutPoint};
use fedimint_bip39::Mnemonic;
use fedimint_core::task::{TaskGroup, TaskHandle, block_in_place};
use fedimint_core::util::{FmtCompact, SafeUrl};
use fedimint_core::{Amount, BitcoinAmountOrAll, crit};
use fedimint_gateway_common::{
    ChainSource, GetInvoiceRequest, GetInvoiceResponse, ListTransactionsResponse,
};
use fedimint_ln_common::contracts::Preimage;
use fedimint_logging::LOG_LIGHTNING;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning::routing::gossip::NodeAlias;
use ldk_node::payment::{PaymentDirection, PaymentKind, PaymentStatus};
use lightning::ln::channelmanager::PaymentId;
use lightning::offers::offer::{Offer, OfferId};
use lightning::routing::router::RouteParametersConfig;
use lightning::types::payment::{PaymentHash, PaymentPreimage};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use tokio::sync::mpsc::Sender;
use tokio::sync::{RwLock, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, warn};

use super::{ChannelInfo, ILnRpcClient, LightningRpcError, ListChannelsResponse, RouteHtlcStream};
use crate::{
    CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, CreateInvoiceRequest,
    CreateInvoiceResponse, GetBalancesResponse, GetLnOnchainAddressResponse, GetNodeInfoResponse,
    GetRouteHintsResponse, InterceptPaymentRequest, InterceptPaymentResponse, InvoiceDescription,
    OpenChannelRequest, OpenChannelResponse, PayInvoiceResponse, PaymentAction, SendOnchainRequest,
    SendOnchainResponse,
};

pub struct GatewayLdkClient {
    /// The underlying lightning node.
    node: Arc<ldk_node::Node>,

    task_group: TaskGroup,

    /// The HTLC stream, until it is taken by calling
    /// `ILnRpcClient::route_htlcs`.
    htlc_stream_receiver_or: Option<tokio::sync::mpsc::Receiver<InterceptPaymentRequest>>,

    /// Lock pool used to ensure that our implementation of `ILnRpcClient::pay`
    /// doesn't allow for multiple simultaneous calls with the same invoice to
    /// execute in parallel. This helps ensure that the function is idempotent.
    outbound_lightning_payment_lock_pool: lockable::LockPool<PaymentId>,

    /// Lock pool used to ensure that our implementation of
    /// `ILnRpcClient::pay_offer` doesn't allow for multiple simultaneous
    /// calls with the same offer to execute in parallel. This helps ensure
    /// that the function is idempotent.
    outbound_offer_lock_pool: lockable::LockPool<LdkOfferId>,

    /// A map keyed by the `UserChannelId` of a channel that is currently
    /// opening. The `Sender` is used to communicate the `OutPoint` back to
    /// the API handler from the event handler when the channel has been
    /// opened and is now pending.
    pending_channels:
        Arc<RwLock<BTreeMap<UserChannelId, oneshot::Sender<anyhow::Result<OutPoint>>>>>,
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
        chain_source: ChainSource,
        network: Network,
        lightning_port: u16,
        alias: String,
        mnemonic: Mnemonic,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> anyhow::Result<Self> {
        let mut bytes = [0u8; 32];
        let alias = if alias.is_empty() {
            "LDK Gateway".to_string()
        } else {
            alias
        };
        let alias_bytes = alias.as_bytes();
        let truncated = &alias_bytes[..alias_bytes.len().min(32)];
        bytes[..truncated.len()].copy_from_slice(truncated);
        let node_alias = Some(NodeAlias(bytes));

        let mut node_builder = ldk_node::Builder::from_config(ldk_node::config::Config {
            network,
            listening_addresses: Some(vec![SocketAddress::TcpIpV4 {
                addr: [0, 0, 0, 0],
                port: lightning_port,
            }]),
            node_alias,
            ..Default::default()
        });

        node_builder.set_entropy_bip39_mnemonic(mnemonic, None);
        node_builder.set_runtime(runtime.handle().clone());

        match chain_source.clone() {
            ChainSource::Bitcoind {
                username,
                password,
                server_url,
            } => {
                node_builder.set_chain_source_bitcoind_rpc(
                    server_url
                        .host_str()
                        .expect("Could not retrieve host from bitcoind RPC url")
                        .to_string(),
                    server_url
                        .port()
                        .expect("Could not retrieve port from bitcoind RPC url"),
                    username,
                    password,
                );
            }
            ChainSource::Esplora { server_url } => {
                node_builder.set_chain_source_esplora(get_esplora_url(server_url)?, None);
            }
        };
        let Some(data_dir_str) = data_dir.to_str() else {
            return Err(anyhow::anyhow!("Invalid data dir path"));
        };
        node_builder.set_storage_dir_path(data_dir_str.to_string());

        info!(chain_source = %chain_source, data_dir = %data_dir_str, alias = %alias, "Starting LDK Node...");
        let node = Arc::new(node_builder.build()?);
        node.start().map_err(|err| {
            crit!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Failed to start LDK Node");
            LightningRpcError::FailedToConnect
        })?;

        let (htlc_stream_sender, htlc_stream_receiver) = tokio::sync::mpsc::channel(1024);
        let task_group = TaskGroup::new();

        let node_clone = node.clone();
        let pending_channels = Arc::new(RwLock::new(BTreeMap::new()));
        let pending_channels_clone = pending_channels.clone();
        task_group.spawn("ldk lightning node event handler", |handle| async move {
            loop {
                Self::handle_next_event(
                    &node_clone,
                    &htlc_stream_sender,
                    &handle,
                    pending_channels_clone.clone(),
                )
                .await;
            }
        });

        info!("Successfully started LDK Gateway");
        Ok(GatewayLdkClient {
            node,
            task_group,
            htlc_stream_receiver_or: Some(htlc_stream_receiver),
            outbound_lightning_payment_lock_pool: lockable::LockPool::new(),
            outbound_offer_lock_pool: lockable::LockPool::new(),
            pending_channels,
        })
    }

    async fn handle_next_event(
        node: &ldk_node::Node,
        htlc_stream_sender: &Sender<InterceptPaymentRequest>,
        handle: &TaskHandle,
        pending_channels: Arc<
            RwLock<BTreeMap<UserChannelId, oneshot::Sender<anyhow::Result<OutPoint>>>>,
        >,
    ) {
        // We manually check for task termination in case we receive a payment while the
        // task is shutting down. In that case, we want to finish the payment
        // before shutting this task down.
        let event = tokio::select! {
            event = node.next_event_async() => {
                event
            }
            () = handle.make_shutdown_rx() => {
                return;
            }
        };

        match event {
            ldk_node::Event::PaymentClaimable {
                payment_id: _,
                payment_hash,
                claimable_amount_msat,
                claim_deadline,
                custom_records: _,
            } => {
                if let Err(err) = htlc_stream_sender
                    .send(InterceptPaymentRequest {
                        payment_hash: Hash::from_slice(&payment_hash.0)
                            .expect("Failed to create Hash"),
                        amount_msat: claimable_amount_msat,
                        expiry: claim_deadline.unwrap_or_default(),
                        short_channel_id: None,
                        incoming_chan_id: 0,
                        htlc_id: 0,
                    })
                    .await
                {
                    warn!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Failed send InterceptHtlcRequest to stream");
                }
            }
            ldk_node::Event::ChannelPending {
                channel_id,
                user_channel_id,
                former_temporary_channel_id: _,
                counterparty_node_id: _,
                funding_txo,
            } => {
                info!(target: LOG_LIGHTNING, %channel_id, "LDK Channel is pending");
                let mut channels = pending_channels.write().await;
                if let Some(sender) = channels.remove(&UserChannelId(user_channel_id)) {
                    let _ = sender.send(Ok(funding_txo));
                } else {
                    debug!(
                        ?user_channel_id,
                        "No channel pending channel open for user channel id"
                    );
                }
            }
            ldk_node::Event::ChannelClosed {
                channel_id,
                user_channel_id,
                counterparty_node_id: _,
                reason,
            } => {
                info!(target: LOG_LIGHTNING, %channel_id, "LDK Channel is closed");
                let mut channels = pending_channels.write().await;
                if let Some(sender) = channels.remove(&UserChannelId(user_channel_id)) {
                    let reason = if let Some(reason) = reason {
                        reason.to_string()
                    } else {
                        "Channel has been closed".to_string()
                    };
                    let _ = sender.send(Err(anyhow::anyhow!(reason)));
                } else {
                    debug!(
                        ?user_channel_id,
                        "No channel pending channel open for user channel id"
                    );
                }
            }
            _ => {}
        }

        // `PaymentClaimable` and `ChannelPending` events are the only event types that
        // we are interested in. We can safely ignore all other events.
        if let Err(err) = node.event_handled() {
            warn!(err = %err.fmt_compact(), "LDK could not mark event handled");
        }
    }
}

impl Drop for GatewayLdkClient {
    fn drop(&mut self) {
        self.task_group.shutdown();

        info!(target: LOG_LIGHTNING, "Stopping LDK Node...");
        match self.node.stop() {
            Err(err) => {
                warn!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Failed to stop LDK Node");
            }
            _ => {
                info!(target: LOG_LIGHTNING, "LDK Node stopped.");
            }
        }
    }
}

#[async_trait]
impl ILnRpcClient for GatewayLdkClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        let node_status = self.node.status();
        let ldk_block_height = node_status.current_best_block.height;
        let onchain_sync = node_status.latest_onchain_wallet_sync_timestamp;
        let lightning_sync = node_status.latest_lightning_wallet_sync_timestamp;
        let is_running = node_status.is_running;
        debug!(target: LOG_LIGHTNING, ?onchain_sync, ?lightning_sync, ?is_running, "LDK Sync Status");

        Ok(GetNodeInfoResponse {
            pub_key: self.node.node_id(),
            alias: match self.node.node_alias() {
                Some(alias) => alias.to_string(),
                None => format!("LDK Fedimint Gateway Node {}", self.node.node_id()),
            },
            network: self.node.config().network.to_string(),
            block_height: ldk_block_height,
            // `synced_to_chain` is used for determining if the Lightning node is ready, so we care
            // about the `lightning_sync` status.
            synced_to_chain: lightning_sync.is_some(),
        })
    }

    async fn routehints(
        &self,
        _num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        // `ILnRpcClient::routehints()` is currently only ever used for LNv1 payment
        // receives and will be removed when we switch to LNv2. The LDK gateway will
        // never support LNv1 payment receives, only LNv2 payment receives, which
        // require that the gateway's lightning node generates invoices rather than the
        // fedimint client, so it is able to insert the proper route hints on its own.
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
        let payment_id = PaymentId(*invoice.payment_hash().as_byte_array());

        // Lock by the payment hash to prevent multiple simultaneous calls with the same
        // invoice from executing. This prevents `ldk-node::Bolt11Payment::send()` from
        // being called multiple times with the same invoice. This is important because
        // `ldk-node::Bolt11Payment::send()` is not idempotent, but this function must
        // be idempotent.
        let _payment_lock_guard = self
            .outbound_lightning_payment_lock_pool
            .async_lock(payment_id)
            .await;

        // If a payment is not known to the node we can initiate it, and if it is known
        // we can skip calling `ldk-node::Bolt11Payment::send()` and wait for the
        // payment to complete. The lock guard above guarantees that this block is only
        // executed once at a time for a given payment hash, ensuring that there is no
        // race condition between checking if a payment is known and initiating a new
        // payment if it isn't.
        let config = RouteParametersConfig::default()
            .with_max_total_routing_fee_msat(max_fee.msats)
            .with_max_total_cltv_expiry_delta(max_delay as u32);
        if self.node.payment(&payment_id).is_none() {
            assert_eq!(
                self.node
                    .bolt11_payment()
                    .send(&invoice, Some(config),)
                    // TODO: Investigate whether all error types returned by `Bolt11Payment::send()`
                    // result in idempotency.
                    .map_err(|e| LightningRpcError::FailedPayment {
                        failure_reason: format!("LDK payment failed to initialize: {e:?}"),
                    })?,
                payment_id
            );
        }

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
                                preimage: Preimage(preimage.0),
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

    async fn complete_htlc(&self, htlc: InterceptPaymentResponse) -> Result<(), LightningRpcError> {
        let InterceptPaymentResponse {
            action,
            payment_hash,
            incoming_chan_id: _,
            htlc_id: _,
        } = htlc;

        let ph = PaymentHash(*payment_hash.clone().as_byte_array());

        // TODO: Get the actual amount from the LDK node. Probably makes the
        // most sense to pipe it through the `InterceptHtlcResponse` struct.
        // This value is only used by `ldk-node` to ensure that the amount
        // claimed isn't less than the amount expected, but we've already
        // verified that the amount is correct when we intercepted the payment.
        let claimable_amount_msat = 999_999_999_999_999;

        let ph_hex_str = hex::encode(payment_hash);

        if let PaymentAction::Settle(preimage) = action {
            self.node
                .bolt11_payment()
                .claim_for_hash(ph, claimable_amount_msat, PaymentPreimage(preimage.0))
                .map_err(|_| LightningRpcError::FailedToCompleteHtlc {
                    failure_reason: format!("Failed to claim LDK payment with hash {ph_hex_str}"),
                })?;
        } else {
            warn!(target: LOG_LIGHTNING, payment_hash = %ph_hex_str, "Unwinding payment because the action was not `Settle`");
            self.node.bolt11_payment().fail_for_hash(ph).map_err(|_| {
                LightningRpcError::FailedToCompleteHtlc {
                    failure_reason: format!("Failed to unwind LDK payment with hash {ph_hex_str}"),
                }
            })?;
        }

        return Ok(());
    }

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        let payment_hash_or = if let Some(payment_hash) = create_invoice_request.payment_hash {
            let ph = PaymentHash(*payment_hash.as_byte_array());
            Some(ph)
        } else {
            None
        };

        let description = match create_invoice_request.description {
            Some(InvoiceDescription::Direct(desc)) => {
                Bolt11InvoiceDescription::Direct(Description::new(desc).map_err(|_| {
                    LightningRpcError::FailedToGetInvoice {
                        failure_reason: "Invalid description".to_string(),
                    }
                })?)
            }
            Some(InvoiceDescription::Hash(hash)) => {
                Bolt11InvoiceDescription::Hash(lightning_invoice::Sha256(hash))
            }
            None => Bolt11InvoiceDescription::Direct(Description::empty()),
        };

        let invoice = match payment_hash_or {
            Some(payment_hash) => self.node.bolt11_payment().receive_for_hash(
                create_invoice_request.amount_msat,
                &description,
                create_invoice_request.expiry_secs,
                payment_hash,
            ),
            None => self.node.bolt11_payment().receive(
                create_invoice_request.amount_msat,
                &description,
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

    async fn send_onchain(
        &self,
        SendOnchainRequest {
            address,
            amount,
            fee_rate_sats_per_vbyte,
        }: SendOnchainRequest,
    ) -> Result<SendOnchainResponse, LightningRpcError> {
        let onchain = self.node.onchain_payment();

        let retain_reserves = false;
        let txid = match amount {
            BitcoinAmountOrAll::All => onchain.send_all_to_address(
                &address.assume_checked(),
                retain_reserves,
                FeeRate::from_sat_per_vb(fee_rate_sats_per_vbyte),
            ),
            BitcoinAmountOrAll::Amount(amount_sats) => onchain.send_to_address(
                &address.assume_checked(),
                amount_sats.to_sat(),
                FeeRate::from_sat_per_vb(fee_rate_sats_per_vbyte),
            ),
        }
        .map_err(|e| LightningRpcError::FailedToWithdrawOnchain {
            failure_reason: e.to_string(),
        })?;

        Ok(SendOnchainResponse {
            txid: txid.to_string(),
        })
    }

    async fn open_channel(
        &self,
        OpenChannelRequest {
            pubkey,
            host,
            channel_size_sats,
            push_amount_sats,
        }: OpenChannelRequest,
    ) -> Result<OpenChannelResponse, LightningRpcError> {
        let push_amount_msats_or = if push_amount_sats == 0 {
            None
        } else {
            Some(push_amount_sats * 1000)
        };

        let (tx, rx) = oneshot::channel::<anyhow::Result<OutPoint>>();

        {
            let mut channels = self.pending_channels.write().await;
            let user_channel_id = self
                .node
                .open_announced_channel(
                    pubkey,
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

            channels.insert(UserChannelId(user_channel_id), tx);
        }

        match rx
            .await
            .map_err(|err| LightningRpcError::FailedToOpenChannel {
                failure_reason: err.to_string(),
            })? {
            Ok(outpoint) => {
                let funding_txid = outpoint.txid;

                Ok(OpenChannelResponse {
                    funding_txid: funding_txid.to_string(),
                })
            }
            Err(err) => Err(LightningRpcError::FailedToOpenChannel {
                failure_reason: err.to_string(),
            }),
        }
    }

    async fn close_channels_with_peer(
        &self,
        CloseChannelsWithPeerRequest {
            pubkey,
            force,
            sats_per_vbyte: _,
        }: CloseChannelsWithPeerRequest,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError> {
        let mut num_channels_closed = 0;

        info!(%pubkey, "Closing all channels with peer");
        for channel_with_peer in self
            .node
            .list_channels()
            .iter()
            .filter(|channel| channel.counterparty_node_id == pubkey)
        {
            if force {
                match self.node.force_close_channel(
                    &channel_with_peer.user_channel_id,
                    pubkey,
                    Some("User initiated force close".to_string()),
                ) {
                    Ok(()) => num_channels_closed += 1,
                    Err(err) => {
                        error!(%pubkey, err = %err.fmt_compact(), "Could not force close channel");
                    }
                }
            } else {
                match self
                    .node
                    .close_channel(&channel_with_peer.user_channel_id, pubkey)
                {
                    Ok(()) => {
                        num_channels_closed += 1;
                    }
                    Err(err) => {
                        error!(%pubkey, err = %err.fmt_compact(), "Could not close channel");
                    }
                }
            }
        }

        Ok(CloseChannelsWithPeerResponse {
            num_channels_closed,
        })
    }

    async fn list_channels(&self) -> Result<ListChannelsResponse, LightningRpcError> {
        let mut channels = Vec::new();

        for channel_details in self.node.list_channels().iter() {
            channels.push(ChannelInfo {
                remote_pubkey: channel_details.counterparty_node_id,
                channel_size_sats: channel_details.channel_value_sats,
                outbound_liquidity_sats: channel_details.outbound_capacity_msat / 1000,
                inbound_liquidity_sats: channel_details.inbound_capacity_msat / 1000,
                is_active: channel_details.is_usable,
                funding_outpoint: channel_details.funding_txo,
            });
        }

        Ok(ListChannelsResponse { channels })
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        let balances = self.node.list_balances();
        let channel_lists = self
            .node
            .list_channels()
            .into_iter()
            .filter(|chan| chan.is_usable)
            .collect::<Vec<_>>();
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

    async fn get_invoice(
        &self,
        get_invoice_request: GetInvoiceRequest,
    ) -> Result<Option<GetInvoiceResponse>, LightningRpcError> {
        let invoices = self
            .node
            .list_payments_with_filter(|details| {
                details.direction == PaymentDirection::Inbound
                    && details.id == PaymentId(get_invoice_request.payment_hash.to_byte_array())
                    && !matches!(details.kind, PaymentKind::Onchain { .. })
            })
            .iter()
            .map(|details| {
                let (preimage, payment_hash, _) = get_preimage_and_payment_hash(&details.kind);
                let status = match details.status {
                    PaymentStatus::Failed => fedimint_gateway_common::PaymentStatus::Failed,
                    PaymentStatus::Succeeded => fedimint_gateway_common::PaymentStatus::Succeeded,
                    PaymentStatus::Pending => fedimint_gateway_common::PaymentStatus::Pending,
                };
                GetInvoiceResponse {
                    preimage: preimage.map(|p| p.to_string()),
                    payment_hash,
                    amount: Amount::from_msats(
                        details
                            .amount_msat
                            .expect("amountless invoices are not supported"),
                    ),
                    created_at: UNIX_EPOCH + Duration::from_secs(details.latest_update_timestamp),
                    status,
                }
            })
            .collect::<Vec<_>>();

        Ok(invoices.first().cloned())
    }

    async fn list_transactions(
        &self,
        start_secs: u64,
        end_secs: u64,
    ) -> Result<ListTransactionsResponse, LightningRpcError> {
        let transactions = self
            .node
            .list_payments_with_filter(|details| {
                !matches!(details.kind, PaymentKind::Onchain { .. })
                    && details.latest_update_timestamp >= start_secs
                    && details.latest_update_timestamp < end_secs
            })
            .iter()
            .map(|details| {
                let (preimage, payment_hash, payment_kind) =
                    get_preimage_and_payment_hash(&details.kind);
                let direction = match details.direction {
                    PaymentDirection::Outbound => {
                        fedimint_gateway_common::PaymentDirection::Outbound
                    }
                    PaymentDirection::Inbound => fedimint_gateway_common::PaymentDirection::Inbound,
                };
                let status = match details.status {
                    PaymentStatus::Failed => fedimint_gateway_common::PaymentStatus::Failed,
                    PaymentStatus::Succeeded => fedimint_gateway_common::PaymentStatus::Succeeded,
                    PaymentStatus::Pending => fedimint_gateway_common::PaymentStatus::Pending,
                };
                fedimint_gateway_common::PaymentDetails {
                    payment_hash,
                    preimage: preimage.map(|p| p.to_string()),
                    payment_kind,
                    amount: Amount::from_msats(
                        details
                            .amount_msat
                            .expect("amountless invoices are not supported"),
                    ),
                    direction,
                    status,
                    timestamp_secs: details.latest_update_timestamp,
                }
            })
            .collect::<Vec<_>>();
        Ok(ListTransactionsResponse { transactions })
    }

    fn create_offer(
        &self,
        amount: Option<Amount>,
        description: Option<String>,
        expiry_secs: Option<u32>,
        quantity: Option<u64>,
    ) -> Result<String, LightningRpcError> {
        let description = description.unwrap_or_default();
        let offer = if let Some(amount) = amount {
            self.node
                .bolt12_payment()
                .receive(amount.msats, &description, expiry_secs, quantity)
                .map_err(|err| LightningRpcError::Bolt12Error {
                    failure_reason: err.to_string(),
                })?
        } else {
            self.node
                .bolt12_payment()
                .receive_variable_amount(&description, expiry_secs)
                .map_err(|err| LightningRpcError::Bolt12Error {
                    failure_reason: err.to_string(),
                })?
        };

        Ok(offer.to_string())
    }

    async fn pay_offer(
        &self,
        offer: String,
        quantity: Option<u64>,
        amount: Option<Amount>,
        payer_note: Option<String>,
    ) -> Result<Preimage, LightningRpcError> {
        let offer = Offer::from_str(&offer).map_err(|_| LightningRpcError::Bolt12Error {
            failure_reason: "Failed to parse Bolt12 Offer".to_string(),
        })?;

        let _offer_lock_guard = self
            .outbound_offer_lock_pool
            .blocking_lock(LdkOfferId(offer.id()));

        let payment_id = if let Some(amount) = amount {
            self.node
                .bolt12_payment()
                .send_using_amount(&offer, amount.msats, quantity, payer_note, None)
                .map_err(|err| LightningRpcError::Bolt12Error {
                    failure_reason: err.to_string(),
                })?
        } else {
            self.node
                .bolt12_payment()
                .send(&offer, quantity, payer_note, None)
                .map_err(|err| LightningRpcError::Bolt12Error {
                    failure_reason: err.to_string(),
                })?
        };

        loop {
            if let Some(payment_details) = self.node.payment(&payment_id) {
                match payment_details.status {
                    PaymentStatus::Pending => {}
                    PaymentStatus::Succeeded => match payment_details.kind {
                        PaymentKind::Bolt12Offer {
                            preimage: Some(preimage),
                            ..
                        } => {
                            info!(target: LOG_LIGHTNING, offer = %offer, payment_id = %payment_id, preimage = %preimage, "Successfully paid offer");
                            return Ok(Preimage(preimage.0));
                        }
                        _ => {
                            return Err(LightningRpcError::FailedPayment {
                                failure_reason: "Unexpected payment kind".to_string(),
                            });
                        }
                    },
                    PaymentStatus::Failed => {
                        return Err(LightningRpcError::FailedPayment {
                            failure_reason: "Bolt12 payment failed".to_string(),
                        });
                    }
                }
            }
            fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
        }
    }

    fn sync_wallet(&self) -> Result<(), LightningRpcError> {
        block_in_place(|| {
            let _ = self.node.sync_wallets();
        });
        Ok(())
    }
}

/// Maps LDK's `PaymentKind` to an optional preimage and an optional payment
/// hash depending on the type of payment.
fn get_preimage_and_payment_hash(
    kind: &PaymentKind,
) -> (
    Option<Preimage>,
    Option<sha256::Hash>,
    fedimint_gateway_common::PaymentKind,
) {
    match kind {
        PaymentKind::Bolt11 {
            hash,
            preimage,
            secret: _,
        } => (
            preimage.map(|p| Preimage(p.0)),
            Some(sha256::Hash::from_slice(&hash.0).expect("Failed to convert payment hash")),
            fedimint_gateway_common::PaymentKind::Bolt11,
        ),
        PaymentKind::Bolt11Jit {
            hash,
            preimage,
            secret: _,
            lsp_fee_limits: _,
            ..
        } => (
            preimage.map(|p| Preimage(p.0)),
            Some(sha256::Hash::from_slice(&hash.0).expect("Failed to convert payment hash")),
            fedimint_gateway_common::PaymentKind::Bolt11,
        ),
        PaymentKind::Bolt12Offer {
            hash,
            preimage,
            secret: _,
            offer_id: _,
            payer_note: _,
            quantity: _,
        } => (
            preimage.map(|p| Preimage(p.0)),
            hash.map(|h| sha256::Hash::from_slice(&h.0).expect("Failed to convert payment hash")),
            fedimint_gateway_common::PaymentKind::Bolt12Offer,
        ),
        PaymentKind::Bolt12Refund {
            hash,
            preimage,
            secret: _,
            payer_note: _,
            quantity: _,
        } => (
            preimage.map(|p| Preimage(p.0)),
            hash.map(|h| sha256::Hash::from_slice(&h.0).expect("Failed to convert payment hash")),
            fedimint_gateway_common::PaymentKind::Bolt12Refund,
        ),
        PaymentKind::Spontaneous { hash, preimage } => (
            preimage.map(|p| Preimage(p.0)),
            Some(sha256::Hash::from_slice(&hash.0).expect("Failed to convert payment hash")),
            fedimint_gateway_common::PaymentKind::Bolt11,
        ),
        PaymentKind::Onchain { .. } => (None, None, fedimint_gateway_common::PaymentKind::Onchain),
    }
}

/// When a port is specified in the Esplora URL, the esplora client inside LDK
/// node cannot connect to the lightning node when there is a trailing slash.
/// The `SafeUrl::Display` function will always serialize the `SafeUrl` with a
/// trailing slash, which causes the connection to fail.
///
/// To handle this, we explicitly construct the esplora URL when a port is
/// specified.
fn get_esplora_url(server_url: SafeUrl) -> anyhow::Result<String> {
    // Esplora client cannot handle trailing slashes
    let host = server_url
        .host_str()
        .ok_or(anyhow::anyhow!("Missing esplora host"))?;
    let server_url = if let Some(port) = server_url.port() {
        format!("{}://{}:{}", server_url.scheme(), host, port)
    } else {
        server_url.to_string()
    };
    Ok(server_url)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct LdkOfferId(OfferId);

impl std::hash::Hash for LdkOfferId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0.0);
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UserChannelId(pub ldk_node::UserChannelId);

impl PartialOrd for UserChannelId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UserChannelId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.0.cmp(&other.0.0)
    }
}

#[cfg(test)]
mod tests;
