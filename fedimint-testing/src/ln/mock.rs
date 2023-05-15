use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{secp256k1, KeyPair};
use fedimint_client_legacy::modules::ln::contracts::Preimage;
use fedimint_core::task::TaskGroup;
use fedimint_core::Amount;
use futures::stream;
use lightning::ln::PaymentSecret;
use lightning_invoice::{Currency, Invoice, InvoiceBuilder, SignedRawInvoice, DEFAULT_EXPIRY_TIME};
use ln_gateway::gatewaylnrpc::{
    self, GetNodeInfoResponse, GetRouteHintsResponse, PayInvoiceRequest, PayInvoiceResponse,
    RouteHtlcRequest,
};
use ln_gateway::lnrpc_client::{ILnRpcClient, RouteHtlcStream};
use ln_gateway::GatewayError;
use rand::rngs::OsRng;
use tokio::sync;
use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;

use super::LightningTest;

#[derive(Clone, Debug)]
pub struct FakeLightningTest {
    pub preimage: Preimage,
    pub gateway_node_pub_key: secp256k1::PublicKey,
    gateway_node_sec_key: secp256k1::SecretKey,
    amount_sent: Arc<Mutex<u64>>,
    task_group: TaskGroup,
}

impl FakeLightningTest {
    pub fn new() -> Self {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let kp = KeyPair::new(&ctx, &mut OsRng);
        let amount_sent = Arc::new(Mutex::new(0));

        FakeLightningTest {
            preimage: Preimage([0; 32]),
            gateway_node_sec_key: SecretKey::from_keypair(&kp),
            gateway_node_pub_key: PublicKey::from_keypair(&kp),
            amount_sent,
            task_group: TaskGroup::new(),
        }
    }
}

impl Default for FakeLightningTest {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LightningTest for FakeLightningTest {
    async fn invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Invoice> {
        let ctx = bitcoin::secp256k1::Secp256k1::new();

        Ok(InvoiceBuilder::new(Currency::Regtest)
            .description("".to_string())
            .payment_hash(sha256::Hash::hash(&self.preimage.0))
            .current_timestamp()
            .min_final_cltv_expiry(0)
            .payment_secret(PaymentSecret([0; 32]))
            .amount_milli_satoshis(amount.msats)
            .expiry_time(Duration::from_secs(
                expiry_time.unwrap_or(DEFAULT_EXPIRY_TIME),
            ))
            .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &self.gateway_node_sec_key))
            .unwrap())
    }

    async fn amount_sent(&self) -> Amount {
        Amount::from_msats(*self.amount_sent.lock().unwrap())
    }

    fn is_shared(&self) -> bool {
        false
    }
}

#[async_trait]
impl ILnRpcClient for FakeLightningTest {
    async fn info(&self) -> ln_gateway::Result<GetNodeInfoResponse> {
        Ok(GetNodeInfoResponse {
            pub_key: self.gateway_node_pub_key.serialize().to_vec(),
            alias: "FakeLightningNode".to_string(),
        })
    }

    async fn routehints(&self) -> ln_gateway::Result<GetRouteHintsResponse> {
        Ok(GetRouteHintsResponse {
            route_hints: vec![gatewaylnrpc::get_route_hints_response::RouteHint { hops: vec![] }],
        })
    }

    async fn pay(&self, invoice: PayInvoiceRequest) -> ln_gateway::Result<PayInvoiceResponse> {
        let signed = invoice.invoice.parse::<SignedRawInvoice>().unwrap();
        let invoice = Invoice::from_signed(signed);
        *self.amount_sent.lock().unwrap() +=
            invoice.clone().unwrap().amount_milli_satoshis().unwrap();

        Ok(PayInvoiceResponse {
            preimage: invoice.unwrap().payment_secret().0.to_vec(),
        })
    }

    async fn route_htlcs<'a>(
        &mut self,
        events: ReceiverStream<RouteHtlcRequest>,
    ) -> Result<RouteHtlcStream<'a>, GatewayError> {
        self.task_group
            .spawn("FakeRoutingThread", |handle| async move {
                let mut stream = events.into_inner();
                while let Some(route_htlc) = stream.recv().await {
                    if handle.is_shutting_down() {
                        break;
                    }
                    tracing::debug!("FakeLightningTest received HTLC message {:?}", route_htlc);
                }
            })
            .await;

        Ok(Box::pin(stream::iter(vec![])))
    }
}

/// A proxy for the underlying LnRpc which can be used to add behavior to it
/// using the "Decorator pattern"
#[derive(Debug, Clone)]
pub struct LnRpcAdapter {
    /// The actual `ILnRpcClient` that we add behavior to.
    client: Arc<RwLock<dyn ILnRpcClient>>,
    /// A pair of [`PayInvoiceRequest`] and `u8` where client.pay() will fail
    /// `u8` times for each `String` (bolt11 invoice)
    fail_invoices: Arc<sync::Mutex<HashMap<String, u8>>>,
}

impl LnRpcAdapter {
    pub fn new(client: Arc<RwLock<dyn ILnRpcClient>>) -> Self {
        let fail_invoices = Arc::new(sync::Mutex::new(HashMap::new()));

        LnRpcAdapter {
            client,
            fail_invoices,
        }
    }

    /// Register `invoice` to fail `times` before (attempt) succeeding. The
    /// invoice will be dropped from the HashMap after succeeding
    #[allow(dead_code)]
    pub async fn fail_invoice(&self, invoice: PayInvoiceRequest, times: u8) {
        self.fail_invoices
            .lock()
            .await
            .insert(invoice.invoice, times + 1);
    }
}

#[async_trait]
impl ILnRpcClient for LnRpcAdapter {
    async fn info(&self) -> ln_gateway::Result<GetNodeInfoResponse> {
        self.client.read().await.info().await
    }

    async fn routehints(&self) -> ln_gateway::Result<GetRouteHintsResponse> {
        self.client.read().await.routehints().await
    }

    async fn pay(&self, invoice: PayInvoiceRequest) -> ln_gateway::Result<PayInvoiceResponse> {
        self.fail_invoices
            .lock()
            .await
            .entry(invoice.invoice.clone())
            .and_modify(|counter| {
                *counter -= 1;
            });
        if let Some(counter) = self.fail_invoices.lock().await.get(&invoice.invoice) {
            if *counter > 0 {
                return Err(GatewayError::Other(anyhow!("expected test error")));
            }
        }
        self.fail_invoices.lock().await.remove(&invoice.invoice);
        self.client.read().await.pay(invoice).await
    }

    async fn route_htlcs<'a>(
        &mut self,
        events: ReceiverStream<RouteHtlcRequest>,
    ) -> Result<RouteHtlcStream<'a>, GatewayError> {
        self.client.write().await.route_htlcs(events).await
    }
}
