//! "None" Lightning backend.
//!
//! An [`ILnRpcClient`] implementation that runs the gateway with no Lightning
//! node attached. It cannot pay or be paid over the Lightning Network.
//!
//! The gateway is still useful for federation-to-federation swaps, where a
//! single gateway is registered with multiple federations and the LNv1/LNv2
//! receive contracts on one federation can be settled by spending an outgoing
//! contract on another. Those paths short-circuit before any LN RPC is invoked
//! (see `is_direct_swap`, `is_lnv1_invoice`, `get_client_for_invoice` in
//! `fedimint-gateway-server`).
//!
//! `info` returns a synthetic identity that is stable across restarts (derived
//! from the gateway mnemonic). `create_invoice` mints a Bolt11 signed by that
//! identity so LNv2 receive offers can register a payment hash with the
//! federation. Everything else returns an error.

use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use async_trait::async_trait;
use bitcoin::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use fedimint_core::Amount;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::BoxStream;
use fedimint_gateway_common::{
    CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, GetInvoiceRequest,
    GetInvoiceResponse, ListTransactionsResponse, OpenChannelRequest, SendOnchainRequest,
};
use fedimint_ln_common::PrunedInvoice;
use fedimint_ln_common::contracts::Preimage;
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use tokio::sync::mpsc;

use crate::{
    CreateInvoiceRequest, CreateInvoiceResponse, GetBalancesResponse, GetLnOnchainAddressResponse,
    GetNodeInfoResponse, GetRouteHintsResponse, ILnRpcClient, InterceptPaymentRequest,
    InterceptPaymentResponse, LightningRpcError, ListChannelsResponse, OpenChannelResponse,
    PayInvoiceResponse, RouteHtlcStream, SendOnchainResponse,
};

const NOT_SUPPORTED: &str = "gateway is running without a Lightning node";

/// Lightning backend used when the gateway has no Lightning node.
pub struct GatewayNoneClient {
    secret_key: SecretKey,
    public_key: PublicKey,
    network: Network,
}

impl std::fmt::Debug for GatewayNoneClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayNoneClient")
            .field("public_key", &self.public_key)
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl GatewayNoneClient {
    /// Build a new client. `seed` is used to derive the synthetic Lightning
    /// identity deterministically (so the gateway has a stable pubkey across
    /// restarts). Callers should pass material that already identifies this
    /// gateway instance, e.g. the bip39 seed.
    pub fn new(seed: &[u8], network: Network) -> Self {
        let secret_key = derive_secret(seed);
        let public_key = secret_key.public_key(&Secp256k1::new());

        Self {
            secret_key,
            public_key,
            network,
        }
    }
}

fn derive_secret(seed: &[u8]) -> SecretKey {
    use bitcoin::hashes::{Hash, HashEngine, sha256};

    // Domain-separated tagged hash so this key cannot collide with any other
    // key derived from the same seed for a different purpose.
    let mut engine = sha256::HashEngine::default();
    engine.input(b"fedimint-lightning-none/v1");
    engine.input(seed);
    let hash = sha256::Hash::from_engine(engine);

    SecretKey::from_slice(hash.as_byte_array())
        .expect("sha256 output is a valid secp256k1 secret key with overwhelming probability")
}

#[async_trait]
impl ILnRpcClient for GatewayNoneClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        Ok(GetNodeInfoResponse {
            pub_key: self.public_key,
            alias: "fedimint-none".to_string(),
            network: self.network.to_string(),
            block_height: 0,
            synced_to_chain: true,
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
        _invoice: lightning_invoice::Bolt11Invoice,
        _max_delay: u64,
        _max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        Err(LightningRpcError::FailedPayment {
            failure_reason: NOT_SUPPORTED.to_string(),
        })
    }

    fn supports_private_payments(&self) -> bool {
        true
    }

    async fn pay_private(
        &self,
        _invoice: PrunedInvoice,
        _max_delay: u64,
        _max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        Err(LightningRpcError::FailedPayment {
            failure_reason: NOT_SUPPORTED.to_string(),
        })
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        let handle = task_group.make_handle();
        let shutdown_receiver = handle.make_shutdown_rx();

        // No Lightning node, so no HTLCs ever arrive. Hold the stream open
        // until shutdown so the consumer doesn't see end-of-stream.
        let (_sender, mut receiver) = mpsc::channel::<InterceptPaymentRequest>(0);
        let stream: BoxStream<'a, InterceptPaymentRequest> = Box::pin(stream! {
            shutdown_receiver.await;
            // Satisfy the type checker; this branch is never taken.
            if let Some(htlc) = receiver.recv().await {
                yield htlc;
            }
        });

        let arc_self = Arc::new(GatewayNoneClient {
            secret_key: self.secret_key,
            public_key: self.public_key,
            network: self.network,
        });
        Ok((stream, arc_self))
    }

    async fn complete_htlc(
        &self,
        _htlc: InterceptPaymentResponse,
    ) -> Result<(), LightningRpcError> {
        Err(LightningRpcError::FailedToCompleteHtlc {
            failure_reason: NOT_SUPPORTED.to_string(),
        })
    }

    async fn create_invoice(
        &self,
        request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        // We must produce a syntactically valid Bolt11 so that `is_direct_swap`
        // can match it against the gateway's own pubkey. The invoice is
        // unpayable from outside (no real route hints, signed by a key that is
        // not announced on the LN gossip network). It is only used as a
        // payment-hash carrier for federation-to-federation swaps.
        let payment_hash =
            request
                .payment_hash
                .ok_or_else(|| LightningRpcError::FailedToGetInvoice {
                    failure_reason: "GatewayNoneClient requires a payment_hash".to_string(),
                })?;

        let ctx = Secp256k1::new();
        let invoice = InvoiceBuilder::new(currency_from_network(self.network))
            .description(String::new())
            .payment_hash(payment_hash)
            .current_timestamp()
            .min_final_cltv_expiry_delta(0)
            .payment_secret(PaymentSecret([0; 32]))
            .amount_milli_satoshis(request.amount_msat)
            .expiry_time(Duration::from_secs(u64::from(request.expiry_secs)))
            .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &self.secret_key))
            .map_err(|e| LightningRpcError::FailedToGetInvoice {
                failure_reason: format!("synthetic invoice signing failed: {e}"),
            })?;

        Ok(CreateInvoiceResponse {
            invoice: invoice.to_string(),
        })
    }

    async fn get_ln_onchain_address(
        &self,
    ) -> Result<GetLnOnchainAddressResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToGetLnOnchainAddress {
            failure_reason: NOT_SUPPORTED.to_string(),
        })
    }

    async fn send_onchain(
        &self,
        _payload: SendOnchainRequest,
    ) -> Result<SendOnchainResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToWithdrawOnchain {
            failure_reason: NOT_SUPPORTED.to_string(),
        })
    }

    async fn open_channel(
        &self,
        _payload: OpenChannelRequest,
    ) -> Result<OpenChannelResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToOpenChannel {
            failure_reason: NOT_SUPPORTED.to_string(),
        })
    }

    async fn close_channels_with_peer(
        &self,
        _payload: CloseChannelsWithPeerRequest,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToCloseChannelsWithPeer {
            failure_reason: NOT_SUPPORTED.to_string(),
        })
    }

    async fn list_channels(&self) -> Result<ListChannelsResponse, LightningRpcError> {
        Ok(ListChannelsResponse { channels: vec![] })
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        Ok(GetBalancesResponse {
            onchain_balance_sats: 0,
            lightning_balance_msats: 0,
            inbound_lightning_liquidity_msats: 0,
        })
    }

    async fn get_invoice(
        &self,
        _request: GetInvoiceRequest,
    ) -> Result<Option<GetInvoiceResponse>, LightningRpcError> {
        Ok(None)
    }

    async fn list_transactions(
        &self,
        _start_secs: u64,
        _end_secs: u64,
    ) -> Result<ListTransactionsResponse, LightningRpcError> {
        Ok(ListTransactionsResponse {
            transactions: vec![],
        })
    }

    fn create_offer(
        &self,
        _amount: Option<Amount>,
        _description: Option<String>,
        _expiry_secs: Option<u32>,
        _quantity: Option<u64>,
    ) -> Result<String, LightningRpcError> {
        Err(LightningRpcError::Bolt12Error {
            failure_reason: NOT_SUPPORTED.to_string(),
        })
    }

    async fn pay_offer(
        &self,
        _offer: String,
        _quantity: Option<u64>,
        _amount: Option<Amount>,
        _payer_note: Option<String>,
    ) -> Result<Preimage, LightningRpcError> {
        Err(LightningRpcError::Bolt12Error {
            failure_reason: NOT_SUPPORTED.to_string(),
        })
    }

    fn sync_wallet(&self) -> Result<(), LightningRpcError> {
        Ok(())
    }
}

fn currency_from_network(network: Network) -> Currency {
    match network {
        Network::Bitcoin => Currency::Bitcoin,
        Network::Testnet => Currency::BitcoinTestnet,
        Network::Signet => Currency::Signet,
        Network::Regtest => Currency::Regtest,
        // Unknown networks default to regtest; this backend is not used in
        // production with mainnet-like settings outside of dev/test anyway.
        _ => Currency::Regtest,
    }
}
