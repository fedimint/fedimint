use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{secp256k1, KeyPair};
use fedimint_client_legacy::modules::ln::contracts::Preimage;
use fedimint_core::task::TaskGroup;
use fedimint_core::Amount;
use futures::stream;
use lightning::ln::PaymentSecret;
use lightning_invoice::{
    Currency, Description, Invoice, InvoiceBuilder, InvoiceDescription, SignedRawInvoice,
    DEFAULT_EXPIRY_TIME,
};
use ln_gateway::gatewaylnrpc::{
    self, GetNodeInfoResponse, GetRouteHintsResponse, PayInvoiceRequest, PayInvoiceResponse,
    RouteHtlcRequest,
};
use ln_gateway::lnrpc_client::{ILnRpcClient, RouteHtlcStream};
use ln_gateway::GatewayError;
use rand::rngs::OsRng;
use tokio_stream::wrappers::ReceiverStream;

use super::LightningTest;

const INVALID_INVOICE_DESCRIPTION: &str = "INVALID";

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

    async fn invalid_invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Invoice> {
        let ctx = bitcoin::secp256k1::Secp256k1::new();

        Ok(InvoiceBuilder::new(Currency::Regtest)
            // In tests we use the description to indicate whether or not we should be able to pay
            // this invoice.
            .description(INVALID_INVOICE_DESCRIPTION.into())
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
        let invoice = Invoice::from_signed(signed).unwrap();
        *self.amount_sent.lock().unwrap() += invoice.clone().amount_milli_satoshis().unwrap();

        if invoice.description()
            == InvoiceDescription::Direct(
                &Description::new(INVALID_INVOICE_DESCRIPTION.into()).unwrap(),
            )
        {
            return Err(GatewayError::Other(anyhow!("Failed to pay invoice")));
        }

        Ok(PayInvoiceResponse {
            preimage: invoice.payment_secret().0.to_vec(),
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
