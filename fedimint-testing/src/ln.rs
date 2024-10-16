use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::KeyPair;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::Address;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::BoxStream;
use fedimint_core::{secp256k1, Amount, BitcoinAmountOrAll};
use fedimint_ln_common::PrunedInvoice;
use fedimint_logging::LOG_TEST;
use lightning_invoice::{
    Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret, DEFAULT_EXPIRY_TIME,
};
use ln_gateway::gateway_lnrpc::{
    self, CloseChannelsWithPeerResponse, CreateInvoiceRequest, CreateInvoiceResponse,
    EmptyResponse, GetBalancesResponse, GetLnOnchainAddressResponse, GetNodeInfoResponse,
    GetRouteHintsResponse, InterceptHtlcResponse, OpenChannelResponse, PayInvoiceResponse,
    WithdrawOnchainResponse,
};
use ln_gateway::lightning::{
    ChannelInfo, HtlcResult, ILnRpcClient, LightningRpcError, RouteHtlcStream,
};
use rand::rngs::OsRng;
use tokio::sync::mpsc;
use tracing::info;

pub const INVALID_INVOICE_PAYMENT_SECRET: [u8; 32] = [212; 32];

pub const MOCK_INVOICE_PREIMAGE: [u8; 32] = [1; 32];

#[derive(Debug)]
pub struct FakeLightningTest {
    pub gateway_node_pub_key: secp256k1::PublicKey,
    gateway_node_sec_key: secp256k1::SecretKey,
    amount_sent: AtomicU64,
}

impl FakeLightningTest {
    pub fn new() -> Self {
        info!(target: LOG_TEST, "Setting up fake lightning test fixture");
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let kp = KeyPair::new(&ctx, &mut OsRng);
        let amount_sent = AtomicU64::new(0);

        FakeLightningTest {
            gateway_node_sec_key: SecretKey::from_keypair(&kp),
            gateway_node_pub_key: PublicKey::from_keypair(&kp),
            amount_sent,
        }
    }
}

impl Default for FakeLightningTest {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeLightningTest {
    pub fn invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Bolt11Invoice> {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let payment_hash = sha256::Hash::hash(&MOCK_INVOICE_PREIMAGE);

        Ok(InvoiceBuilder::new(Currency::Regtest)
            .description(String::new())
            .payment_hash(payment_hash)
            .current_timestamp()
            .min_final_cltv_expiry_delta(0)
            .payment_secret(PaymentSecret([0; 32]))
            .amount_milli_satoshis(amount.msats)
            .expiry_time(Duration::from_secs(
                expiry_time.unwrap_or(DEFAULT_EXPIRY_TIME),
            ))
            .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &self.gateway_node_sec_key))
            .unwrap())
    }

    /// Creates an invoice that is not payable
    ///
    /// * Mocks use hard-coded invoice description to fail the payment
    /// * Real fixtures won't be able to route to randomly generated node pubkey
    pub fn unpayable_invoice(&self, amount: Amount, expiry_time: Option<u64>) -> Bolt11Invoice {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        // Generate fake node keypair
        let kp = KeyPair::new(&ctx, &mut OsRng);
        let payment_hash = sha256::Hash::hash(&MOCK_INVOICE_PREIMAGE);

        // `FakeLightningTest` will fail to pay any invoice with
        // `INVALID_INVOICE_DESCRIPTION` in the description of the invoice.
        InvoiceBuilder::new(Currency::Regtest)
            .payee_pub_key(kp.public_key())
            .description("INVALID INVOICE DESCRIPTION".to_string())
            .payment_hash(payment_hash)
            .current_timestamp()
            .min_final_cltv_expiry_delta(0)
            .payment_secret(PaymentSecret(INVALID_INVOICE_PAYMENT_SECRET))
            .amount_milli_satoshis(amount.msats)
            .expiry_time(Duration::from_secs(
                expiry_time.unwrap_or(DEFAULT_EXPIRY_TIME),
            ))
            .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &SecretKey::from_keypair(&kp)))
            .expect("Invoice creation failed")
    }

    pub fn listening_address(&self) -> String {
        "FakeListeningAddress".to_string()
    }
}

#[async_trait]
impl ILnRpcClient for FakeLightningTest {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        Ok(GetNodeInfoResponse {
            pub_key: self.gateway_node_pub_key.serialize().to_vec(),
            alias: "FakeLightningNode".to_string(),
            network: "regtest".to_string(),
            block_height: 0,
            synced_to_chain: false,
        })
    }

    async fn routehints(
        &self,
        _num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        Ok(GetRouteHintsResponse {
            route_hints: vec![gateway_lnrpc::get_route_hints_response::RouteHint { hops: vec![] }],
        })
    }

    async fn pay(
        &self,
        invoice: Bolt11Invoice,
        _max_delay: u64,
        _max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        self.amount_sent.fetch_add(
            invoice
                .amount_milli_satoshis()
                .expect("Invoice missing amount"),
            Ordering::Relaxed,
        );

        if *invoice.payment_secret() == PaymentSecret(INVALID_INVOICE_PAYMENT_SECRET) {
            return Err(LightningRpcError::FailedPayment {
                failure_reason: "Invoice was invalid".to_string(),
            });
        }

        Ok(PayInvoiceResponse {
            preimage: MOCK_INVOICE_PREIMAGE.to_vec(),
        })
    }

    fn supports_private_payments(&self) -> bool {
        true
    }

    async fn pay_private(
        &self,
        invoice: PrunedInvoice,
        _max_delay: u64,
        _max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        self.amount_sent
            .fetch_add(invoice.amount.msats, Ordering::Relaxed);

        if invoice.payment_secret == INVALID_INVOICE_PAYMENT_SECRET {
            return Err(LightningRpcError::FailedPayment {
                failure_reason: "Invoice was invalid".to_string(),
            });
        }

        Ok(PayInvoiceResponse {
            preimage: MOCK_INVOICE_PREIMAGE.to_vec(),
        })
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        let handle = task_group.make_handle();
        let shutdown_receiver = handle.make_shutdown_rx();

        // `FakeLightningTest` will never intercept any HTLCs because there is no
        // lightning connection, so instead we just create a stream that blocks
        // until the task group is shutdown.
        let (_, mut receiver) = mpsc::channel::<HtlcResult>(0);
        let stream: BoxStream<'a, HtlcResult> = Box::pin(stream! {
            shutdown_receiver.await;
            // This block, and `receiver`, exist solely to satisfy the type checker.
            if let Some(htlc_result) = receiver.recv().await {
                yield htlc_result;
            }
        });
        Ok((stream, Arc::new(Self::new())))
    }

    async fn complete_htlc(
        &self,
        _htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        Ok(EmptyResponse {})
    }

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        let ctx = bitcoin::secp256k1::Secp256k1::new();

        let payment_hash_or = if create_invoice_request.payment_hash.is_empty() {
            None
        } else {
            Some(
                sha256::Hash::from_slice(&create_invoice_request.payment_hash).map_err(|e| {
                    LightningRpcError::FailedToGetInvoice {
                        failure_reason: format!(
                            "CreateInvoiceRequest.payment_hash is invalid: {e}"
                        ),
                    }
                })?,
            )
        };

        let invoice = match payment_hash_or {
            Some(payment_hash) => InvoiceBuilder::new(Currency::Regtest)
                .description(String::new())
                .payment_hash(payment_hash)
                .current_timestamp()
                .min_final_cltv_expiry_delta(0)
                .payment_secret(PaymentSecret([0; 32]))
                .amount_milli_satoshis(create_invoice_request.amount_msat)
                .expiry_time(Duration::from_secs(u64::from(
                    create_invoice_request.expiry_secs,
                )))
                .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &self.gateway_node_sec_key))
                .unwrap(),
            None => {
                return Err(LightningRpcError::FailedToGetInvoice {
                    failure_reason: "FakeLightningTest does not support creating invoices without a payment hash".to_string(),
                });
            }
        };

        Ok(CreateInvoiceResponse {
            invoice: invoice.to_string(),
        })
    }

    async fn get_ln_onchain_address(
        &self,
    ) -> Result<GetLnOnchainAddressResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToGetLnOnchainAddress {
            failure_reason: "FakeLightningTest does not support getting a funding address"
                .to_string(),
        })
    }

    async fn withdraw_onchain(
        &self,
        _address: Address,
        _amount: BitcoinAmountOrAll,
        _fee_rate_sats_per_vbyte: u64,
    ) -> Result<WithdrawOnchainResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToWithdrawOnchain {
            failure_reason: "FakeLightningTest does not support withdrawing funds on-chain"
                .to_string(),
        })
    }

    async fn open_channel(
        &self,
        _pubkey: bitcoin::secp256k1::PublicKey,
        _host: String,
        _channel_size_sats: u64,
        _push_amount_sats: u64,
    ) -> Result<OpenChannelResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToOpenChannel {
            failure_reason: "FakeLightningTest does not support opening channels".to_string(),
        })
    }

    async fn close_channels_with_peer(
        &self,
        _pubkey: bitcoin::secp256k1::PublicKey,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToCloseChannelsWithPeer {
            failure_reason: "FakeLightningTest does not support closing channels by peer"
                .to_string(),
        })
    }

    async fn list_active_channels(&self) -> Result<Vec<ChannelInfo>, LightningRpcError> {
        Err(LightningRpcError::FailedToListActiveChannels {
            failure_reason: "FakeLightningTest does not support listing active channels"
                .to_string(),
        })
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToGetBalances {
            failure_reason: "FakeLightningTest does not support getting balances".to_string(),
        })
    }
}
