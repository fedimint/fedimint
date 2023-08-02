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
    self, EmptyResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcResponse,
    PayInvoiceRequest, PayInvoiceResponse,
};
use ln_gateway::lnrpc_client::{ILnRpcClient, LightningRpcError, RouteHtlcStream};
use rand::rngs::OsRng;

use super::LightningTest;

pub const INVALID_INVOICE_DESCRIPTION: &str = "INVALID";

#[derive(Clone, Debug)]
pub struct FakeLightningTest {
    pub preimage: Preimage,
    pub gateway_node_pub_key: secp256k1::PublicKey,
    gateway_node_sec_key: secp256k1::SecretKey,
    amount_sent: Arc<Mutex<u64>>,
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

    fn is_shared(&self) -> bool {
        false
    }

    fn listening_address(&self) -> String {
        "FakeListeningAddress".to_string()
    }
}

#[async_trait]
impl ILnRpcClient for FakeLightningTest {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        Ok(GetNodeInfoResponse {
            pub_key: self.gateway_node_pub_key.serialize().to_vec(),
            alias: "FakeLightningNode".to_string(),
        })
    }

    async fn routehints(&self) -> Result<GetRouteHintsResponse, LightningRpcError> {
        Ok(GetRouteHintsResponse {
            route_hints: vec![gatewaylnrpc::get_route_hints_response::RouteHint { hops: vec![] }],
        })
    }

    async fn pay(
        &self,
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let signed = invoice.invoice.parse::<SignedRawInvoice>().unwrap();
        let invoice = Invoice::from_signed(signed).unwrap();
        *self.amount_sent.lock().unwrap() += invoice.amount_milli_satoshis().unwrap();

        if invoice.description()
            == InvoiceDescription::Direct(
                &Description::new(INVALID_INVOICE_DESCRIPTION.into()).unwrap(),
            )
        {
            return Err(LightningRpcError::FailedPayment {
                failure_reason: "Description was invalid".to_string(),
            });
        }

        Ok(PayInvoiceResponse {
            preimage: [0; 32].to_vec(),
        })
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        _task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        Ok((Box::pin(stream::iter(vec![])), Arc::new(Self::new())))
    }

    async fn complete_htlc(
        &self,
        _htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        Ok(EmptyResponse {})
    }
}
