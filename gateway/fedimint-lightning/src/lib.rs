pub mod ldk;
pub mod lnd;
pub mod metrics;

use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::Network;
use bitcoin::hashes::sha256;
use fedimint_core::Amount;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::{FM_IN_DEVIMINT_ENV, is_env_var_set};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::{backoff_util, retry};
use fedimint_gateway_common::{
    ChannelInfo, CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, GetInvoiceRequest,
    GetInvoiceResponse, LightningInfo, ListTransactionsResponse, OpenChannelRequest,
    SendOnchainRequest,
};
use fedimint_ln_common::PrunedInvoice;
pub use fedimint_ln_common::contracts::Preimage;
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_logging::LOG_LIGHTNING;
use fedimint_metrics::HistogramExt as _;
use futures::stream::BoxStream;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

pub const MAX_LIGHTNING_RETRIES: u32 = 10;

pub type RouteHtlcStream<'a> = BoxStream<'a, InterceptPaymentRequest>;

#[derive(
    Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq, Hash,
)]
pub enum LightningRpcError {
    #[error("Failed to connect to Lightning node")]
    FailedToConnect,
    #[error("Failed to retrieve node info: {failure_reason}")]
    FailedToGetNodeInfo { failure_reason: String },
    #[error("Failed to retrieve route hints: {failure_reason}")]
    FailedToGetRouteHints { failure_reason: String },
    #[error("Payment failed: {failure_reason}")]
    FailedPayment { failure_reason: String },
    #[error("Failed to route HTLCs: {failure_reason}")]
    FailedToRouteHtlcs { failure_reason: String },
    #[error("Failed to complete HTLC: {failure_reason}")]
    FailedToCompleteHtlc { failure_reason: String },
    #[error("Failed to open channel: {failure_reason}")]
    FailedToOpenChannel { failure_reason: String },
    #[error("Failed to close channel: {failure_reason}")]
    FailedToCloseChannelsWithPeer { failure_reason: String },
    #[error("Failed to get Invoice: {failure_reason}")]
    FailedToGetInvoice { failure_reason: String },
    #[error("Failed to list transactions: {failure_reason}")]
    FailedToListTransactions { failure_reason: String },
    #[error("Failed to get funding address: {failure_reason}")]
    FailedToGetLnOnchainAddress { failure_reason: String },
    #[error("Failed to withdraw funds on-chain: {failure_reason}")]
    FailedToWithdrawOnchain { failure_reason: String },
    #[error("Failed to connect to peer: {failure_reason}")]
    FailedToConnectToPeer { failure_reason: String },
    #[error("Failed to list active channels: {failure_reason}")]
    FailedToListChannels { failure_reason: String },
    #[error("Failed to get balances: {failure_reason}")]
    FailedToGetBalances { failure_reason: String },
    #[error("Failed to sync to chain: {failure_reason}")]
    FailedToSyncToChain { failure_reason: String },
    #[error("Invalid metadata: {failure_reason}")]
    InvalidMetadata { failure_reason: String },
    #[error("Bolt12 Error: {failure_reason}")]
    Bolt12Error { failure_reason: String },
}

/// Represents an active connection to the lightning node.
#[derive(Clone, Debug)]
pub struct LightningContext {
    pub lnrpc: Arc<dyn ILnRpcClient>,
    pub lightning_public_key: PublicKey,
    pub lightning_alias: String,
    pub lightning_network: Network,
}

/// A trait that the gateway uses to interact with a lightning node. This allows
/// the gateway to be agnostic to the specific lightning node implementation
/// being used.
#[async_trait]
pub trait ILnRpcClient: Debug + Send + Sync {
    /// Returns high-level info about the lightning node.
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError>;

    /// Returns route hints to the lightning node.
    ///
    /// Note: This is only used for inbound LNv1 payments and will be removed
    /// when we switch to LNv2.
    async fn routehints(
        &self,
        num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError>;

    /// Attempts to pay an invoice using the lightning node, waiting for the
    /// payment to complete and returning the preimage.
    ///
    /// Caller restrictions:
    /// May be called multiple times for the same invoice, but _should_ be done
    /// with all the same parameters. This is because the payment may be
    /// in-flight from a previous call, in which case fee or delay limits cannot
    /// be changed and will be ignored.
    ///
    /// Implementor restrictions:
    /// This _must_ be idempotent for a given invoice, since it is called by
    /// state machines. In more detail, when called for a given invoice:
    /// * If the payment is already in-flight, wait for that payment to complete
    ///   as if it were the first call.
    /// * If the payment has already been attempted and failed, return an error.
    /// * If the payment has already succeeded, return a success response.
    async fn pay(
        &self,
        invoice: Bolt11Invoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        self.pay_private(
            PrunedInvoice::try_from(invoice).map_err(|_| LightningRpcError::FailedPayment {
                failure_reason: "Invoice has no amount".to_string(),
            })?,
            max_delay,
            max_fee,
        )
        .await
    }

    /// Attempts to pay an invoice using the lightning node, waiting for the
    /// payment to complete and returning the preimage.
    ///
    /// This is more private than [`ILnRpcClient::pay`], as it does not require
    /// the invoice description. If this is implemented,
    /// [`ILnRpcClient::supports_private_payments`] must return true.
    ///
    /// Note: This is only used for outbound LNv1 payments and will be removed
    /// when we switch to LNv2.
    async fn pay_private(
        &self,
        _invoice: PrunedInvoice,
        _max_delay: u64,
        _max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        Err(LightningRpcError::FailedPayment {
            failure_reason: "Private payments not supported".to_string(),
        })
    }

    /// Returns true if the lightning backend supports payments without full
    /// invoices. If this returns true, [`ILnRpcClient::pay_private`] must
    /// be implemented.
    fn supports_private_payments(&self) -> bool {
        false
    }

    /// Consumes the current client and returns a stream of intercepted HTLCs
    /// and a new client. `complete_htlc` must be called for all successfully
    /// intercepted HTLCs sent to the returned stream.
    ///
    /// `route_htlcs` can only be called once for a given client, since the
    /// returned stream grants exclusive routing decisions to the caller.
    /// For this reason, `route_htlc` consumes the client and returns one
    /// wrapped in an `Arc`. This lets the compiler enforce that `route_htlcs`
    /// can only be called once for a given client, since the value inside
    /// the `Arc` cannot be consumed.
    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError>;

    /// Completes an HTLC that was intercepted by the gateway. Must be called
    /// for all successfully intercepted HTLCs sent to the stream returned
    /// by `route_htlcs`.
    async fn complete_htlc(&self, htlc: InterceptPaymentResponse) -> Result<(), LightningRpcError>;

    /// Requests the lightning node to create an invoice. The presence of a
    /// payment hash in the `CreateInvoiceRequest` determines if the invoice is
    /// intended to be an ecash payment or a direct payment to this lightning
    /// node.
    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError>;

    /// Gets a funding address belonging to the lightning node's on-chain
    /// wallet.
    async fn get_ln_onchain_address(
        &self,
    ) -> Result<GetLnOnchainAddressResponse, LightningRpcError>;

    /// Executes an onchain transaction using the lightning node's on-chain
    /// wallet.
    async fn send_onchain(
        &self,
        payload: SendOnchainRequest,
    ) -> Result<SendOnchainResponse, LightningRpcError>;

    /// Opens a channel with a peer lightning node.
    async fn open_channel(
        &self,
        payload: OpenChannelRequest,
    ) -> Result<OpenChannelResponse, LightningRpcError>;

    /// Closes all channels with a peer lightning node.
    async fn close_channels_with_peer(
        &self,
        payload: CloseChannelsWithPeerRequest,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError>;

    /// Lists the lightning node's active channels with all peers.
    async fn list_channels(&self) -> Result<ListChannelsResponse, LightningRpcError>;

    /// Returns a summary of the lightning node's balance, including the onchain
    /// wallet, outbound liquidity, and inbound liquidity.
    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError>;

    async fn get_invoice(
        &self,
        get_invoice_request: GetInvoiceRequest,
    ) -> Result<Option<GetInvoiceResponse>, LightningRpcError>;

    async fn list_transactions(
        &self,
        start_secs: u64,
        end_secs: u64,
    ) -> Result<ListTransactionsResponse, LightningRpcError>;

    fn create_offer(
        &self,
        amount: Option<Amount>,
        description: Option<String>,
        expiry_secs: Option<u32>,
        quantity: Option<u64>,
    ) -> Result<String, LightningRpcError>;

    async fn pay_offer(
        &self,
        offer: String,
        quantity: Option<u64>,
        amount: Option<Amount>,
        payer_note: Option<String>,
    ) -> Result<Preimage, LightningRpcError>;

    fn sync_wallet(&self) -> Result<(), LightningRpcError>;
}

impl dyn ILnRpcClient {
    /// Retrieve route hints from the Lightning node, capped at
    /// `num_route_hints`. The route hints should be ordered based on liquidity
    /// of incoming channels.
    pub async fn parsed_route_hints(&self, num_route_hints: u32) -> Vec<RouteHint> {
        if num_route_hints == 0 {
            return vec![];
        }

        let route_hints =
            self.routehints(num_route_hints as usize)
                .await
                .unwrap_or(GetRouteHintsResponse {
                    route_hints: Vec::new(),
                });
        route_hints.route_hints
    }

    /// Retrieves the basic information about the Gateway's connected Lightning
    /// node.
    pub async fn parsed_node_info(&self) -> LightningInfo {
        if let Ok(info) = self.info().await
            && let Ok(network) =
                Network::from_str(&info.network).map_err(|e| LightningRpcError::InvalidMetadata {
                    failure_reason: format!("Invalid network {}: {e}", info.network),
                })
        {
            return LightningInfo::Connected {
                public_key: info.pub_key,
                alias: info.alias,
                network,
                block_height: info.block_height as u64,
                synced_to_chain: info.synced_to_chain,
            };
        }

        LightningInfo::NotConnected
    }

    /// Waits for the Lightning node to be synced to the Bitcoin blockchain.
    pub async fn wait_for_chain_sync(&self) -> std::result::Result<(), LightningRpcError> {
        // In devimint, we explicitly sync the onchain wallet to start the sync quicker
        // than background sync would. In production, background sync is
        // sufficient
        if is_env_var_set(FM_IN_DEVIMINT_ENV) {
            self.sync_wallet()?;
        }

        // Wait for the Lightning node to sync
        retry(
            "Wait for chain sync",
            backoff_util::background_backoff(),
            || async {
                let info = self.info().await?;
                let block_height = info.block_height;
                if info.synced_to_chain {
                    Ok(())
                } else {
                    warn!(target: LOG_LIGHTNING, block_height = %block_height, "Lightning node is not synced yet");
                    Err(anyhow::anyhow!("Not synced yet"))
                }
            },
        )
        .await
        .map_err(|e| LightningRpcError::FailedToSyncToChain {
            failure_reason: format!("Failed to sync to chain: {e:?}"),
        })?;

        info!(target: LOG_LIGHTNING, "Gateway successfully synced with the chain");
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetNodeInfoResponse {
    pub pub_key: PublicKey,
    pub alias: String,
    pub network: String,
    pub block_height: u32,
    pub synced_to_chain: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InterceptPaymentRequest {
    pub payment_hash: sha256::Hash,
    pub amount_msat: u64,
    pub expiry: u32,
    pub incoming_chan_id: u64,
    pub short_channel_id: Option<u64>,
    pub htlc_id: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InterceptPaymentResponse {
    pub incoming_chan_id: u64,
    pub htlc_id: u64,
    pub payment_hash: sha256::Hash,
    pub action: PaymentAction,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PaymentAction {
    Settle(Preimage),
    Cancel,
    Forward,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetRouteHintsResponse {
    pub route_hints: Vec<RouteHint>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PayInvoiceResponse {
    pub preimage: Preimage,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateInvoiceRequest {
    pub payment_hash: Option<sha256::Hash>,
    pub amount_msat: u64,
    pub expiry_secs: u32,
    pub description: Option<InvoiceDescription>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum InvoiceDescription {
    Direct(String),
    Hash(sha256::Hash),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateInvoiceResponse {
    pub invoice: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetLnOnchainAddressResponse {
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendOnchainResponse {
    pub txid: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenChannelResponse {
    pub funding_txid: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ListChannelsResponse {
    pub channels: Vec<ChannelInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetBalancesResponse {
    pub onchain_balance_sats: u64,
    pub lightning_balance_msats: u64,
    pub inbound_lightning_liquidity_msats: u64,
}

/// A wrapper around `Arc<dyn ILnRpcClient>` that tracks metrics for each RPC
/// call.
///
/// This wrapper records the duration and success/error status of each
/// Lightning RPC call to Prometheus metrics, allowing monitoring of
/// Lightning node connectivity and performance.
///
/// Note: This wrapper is designed to wrap the `Arc<dyn ILnRpcClient>` returned
/// from `route_htlcs`. Calling `route_htlcs` on this wrapper will panic, as
/// `route_htlcs` should only be called once on the original client before
/// wrapping.
pub struct LnRpcTracked {
    inner: Arc<dyn ILnRpcClient>,
    name: &'static str,
}

impl std::fmt::Debug for LnRpcTracked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LnRpcTracked")
            .field("name", &self.name)
            .field("inner", &self.inner)
            .finish()
    }
}

impl LnRpcTracked {
    /// Wraps an `Arc<dyn ILnRpcClient>` with metrics tracking.
    ///
    /// The `name` parameter is used to distinguish different uses of the
    /// Lightning RPC client in metrics (e.g., "gateway").
    #[allow(clippy::new_ret_no_self)]
    pub fn new(inner: Arc<dyn ILnRpcClient>, name: &'static str) -> Arc<dyn ILnRpcClient> {
        Arc::new(Self { inner, name })
    }

    fn record_call<T, E>(&self, method: &str, result: &Result<T, E>) {
        let result_label = if result.is_ok() { "success" } else { "error" };
        metrics::LN_RPC_REQUESTS_TOTAL
            .with_label_values(&[method, self.name, result_label])
            .inc();
    }
}

#[async_trait]
impl ILnRpcClient for LnRpcTracked {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["info", self.name])
            .start_timer_ext();
        let result = self.inner.info().await;
        timer.observe_duration();
        self.record_call("info", &result);
        result
    }

    async fn routehints(
        &self,
        num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["routehints", self.name])
            .start_timer_ext();
        let result = self.inner.routehints(num_route_hints).await;
        timer.observe_duration();
        self.record_call("routehints", &result);
        result
    }

    async fn pay(
        &self,
        invoice: Bolt11Invoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["pay", self.name])
            .start_timer_ext();
        let result = self.inner.pay(invoice, max_delay, max_fee).await;
        timer.observe_duration();
        self.record_call("pay", &result);
        result
    }

    async fn pay_private(
        &self,
        invoice: PrunedInvoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["pay_private", self.name])
            .start_timer_ext();
        let result = self.inner.pay_private(invoice, max_delay, max_fee).await;
        timer.observe_duration();
        self.record_call("pay_private", &result);
        result
    }

    fn supports_private_payments(&self) -> bool {
        self.inner.supports_private_payments()
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        _task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        // route_htlcs should only be called once on the original client before
        // wrapping with LnRpcTracked. The Arc returned from route_htlcs should
        // be wrapped with LnRpcTracked::new.
        panic!(
            "route_htlcs should not be called on LnRpcTracked. \
             Wrap the Arc returned from route_htlcs instead."
        );
    }

    async fn complete_htlc(&self, htlc: InterceptPaymentResponse) -> Result<(), LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["complete_htlc", self.name])
            .start_timer_ext();
        let result = self.inner.complete_htlc(htlc).await;
        timer.observe_duration();
        self.record_call("complete_htlc", &result);
        result
    }

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["create_invoice", self.name])
            .start_timer_ext();
        let result = self.inner.create_invoice(create_invoice_request).await;
        timer.observe_duration();
        self.record_call("create_invoice", &result);
        result
    }

    async fn get_ln_onchain_address(
        &self,
    ) -> Result<GetLnOnchainAddressResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["get_ln_onchain_address", self.name])
            .start_timer_ext();
        let result = self.inner.get_ln_onchain_address().await;
        timer.observe_duration();
        self.record_call("get_ln_onchain_address", &result);
        result
    }

    async fn send_onchain(
        &self,
        payload: SendOnchainRequest,
    ) -> Result<SendOnchainResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["send_onchain", self.name])
            .start_timer_ext();
        let result = self.inner.send_onchain(payload).await;
        timer.observe_duration();
        self.record_call("send_onchain", &result);
        result
    }

    async fn open_channel(
        &self,
        payload: OpenChannelRequest,
    ) -> Result<OpenChannelResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["open_channel", self.name])
            .start_timer_ext();
        let result = self.inner.open_channel(payload).await;
        timer.observe_duration();
        self.record_call("open_channel", &result);
        result
    }

    async fn close_channels_with_peer(
        &self,
        payload: CloseChannelsWithPeerRequest,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["close_channels_with_peer", self.name])
            .start_timer_ext();
        let result = self.inner.close_channels_with_peer(payload).await;
        timer.observe_duration();
        self.record_call("close_channels_with_peer", &result);
        result
    }

    async fn list_channels(&self) -> Result<ListChannelsResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["list_channels", self.name])
            .start_timer_ext();
        let result = self.inner.list_channels().await;
        timer.observe_duration();
        self.record_call("list_channels", &result);
        result
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["get_balances", self.name])
            .start_timer_ext();
        let result = self.inner.get_balances().await;
        timer.observe_duration();
        self.record_call("get_balances", &result);
        result
    }

    async fn get_invoice(
        &self,
        get_invoice_request: GetInvoiceRequest,
    ) -> Result<Option<GetInvoiceResponse>, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["get_invoice", self.name])
            .start_timer_ext();
        let result = self.inner.get_invoice(get_invoice_request).await;
        timer.observe_duration();
        self.record_call("get_invoice", &result);
        result
    }

    async fn list_transactions(
        &self,
        start_secs: u64,
        end_secs: u64,
    ) -> Result<ListTransactionsResponse, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["list_transactions", self.name])
            .start_timer_ext();
        let result = self.inner.list_transactions(start_secs, end_secs).await;
        timer.observe_duration();
        self.record_call("list_transactions", &result);
        result
    }

    fn create_offer(
        &self,
        amount: Option<Amount>,
        description: Option<String>,
        expiry_secs: Option<u32>,
        quantity: Option<u64>,
    ) -> Result<String, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["create_offer", self.name])
            .start_timer_ext();
        let result = self
            .inner
            .create_offer(amount, description, expiry_secs, quantity);
        timer.observe_duration();
        self.record_call("create_offer", &result);
        result
    }

    async fn pay_offer(
        &self,
        offer: String,
        quantity: Option<u64>,
        amount: Option<Amount>,
        payer_note: Option<String>,
    ) -> Result<Preimage, LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["pay_offer", self.name])
            .start_timer_ext();
        let result = self
            .inner
            .pay_offer(offer, quantity, amount, payer_note)
            .await;
        timer.observe_duration();
        self.record_call("pay_offer", &result);
        result
    }

    fn sync_wallet(&self) -> Result<(), LightningRpcError> {
        let timer = metrics::LN_RPC_DURATION_SECONDS
            .with_label_values(&["sync_wallet", self.name])
            .start_timer_ext();
        let result = self.inner.sync_wallet();
        timer.observe_duration();
        self.record_call("sync_wallet", &result);
        result
    }
}
