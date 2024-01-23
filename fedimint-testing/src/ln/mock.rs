use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_stream::stream;
use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{secp256k1, KeyPair};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::BoxStream;
use fedimint_core::Amount;
use fedimint_logging::LOG_TEST;
use lightning_invoice::{
    Bolt11Invoice, Bolt11InvoiceDescription, Currency, Description, InvoiceBuilder, PaymentSecret,
    SignedRawBolt11Invoice, DEFAULT_EXPIRY_TIME,
};
use ln_gateway::gateway_lnrpc::{
    self, EmptyResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcResponse,
    PayInvoiceRequest, PayInvoiceResponse,
};
use ln_gateway::lightning::cln::{HtlcResult, RouteHtlcStream};
use ln_gateway::lightning::{ILnRpcClient, LightningRpcError};
use rand::rngs::OsRng;
use tokio::sync::mpsc;
use tracing::info;

use super::LightningTest;
use crate::gateway::LightningNodeType;

pub const INVALID_INVOICE_DESCRIPTION: &str = "INVALID";

#[derive(Debug)]
pub struct FakeLightningTest {
    pub gateway_node_pub_key: secp256k1::PublicKey,
    gateway_node_sec_key: secp256k1::SecretKey,
    amount_sent: Arc<Mutex<u64>>,
    receiver: mpsc::Receiver<HtlcResult>,
}

impl FakeLightningTest {
    pub fn new() -> Self {
        info!(target: LOG_TEST, "Setting up fake lightning test fixture");
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let kp = KeyPair::new(&ctx, &mut OsRng);
        let amount_sent = Arc::new(Mutex::new(0));
        let (_, receiver) = mpsc::channel::<HtlcResult>(10);

        FakeLightningTest {
            gateway_node_sec_key: SecretKey::from_keypair(&kp),
            gateway_node_pub_key: PublicKey::from_keypair(&kp),
            amount_sent,
            receiver,
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
    ) -> ln_gateway::Result<Bolt11Invoice> {
        let ctx = bitcoin::secp256k1::Secp256k1::new();

        Ok(InvoiceBuilder::new(Currency::Regtest)
            .description("".to_string())
            .payment_hash(sha256::Hash::hash(&[0; 32]))
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

    fn is_shared(&self) -> bool {
        false
    }

    fn listening_address(&self) -> String {
        "FakeListeningAddress".to_string()
    }

    fn lightning_node_type(&self) -> LightningNodeType {
        unimplemented!("FakeLightningTest does not have a lightning node type")
    }
}

#[async_trait]
impl ILnRpcClient for FakeLightningTest {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        Ok(GetNodeInfoResponse {
            pub_key: self.gateway_node_pub_key.serialize().to_vec(),
            alias: "FakeLightningNode".to_string(),
            network: "regtest".to_string(),
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
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let signed = invoice.invoice.parse::<SignedRawBolt11Invoice>().unwrap();
        let invoice = Bolt11Invoice::from_signed(signed).unwrap();
        *self.amount_sent.lock().unwrap() += invoice.amount_milli_satoshis().unwrap();

        if invoice.description()
            == Bolt11InvoiceDescription::Direct(
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
        mut self: Box<Self>,
        task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        let handle = task_group.make_handle();
        let shutdown_receiver = handle.make_shutdown_rx().await;

        // `FakeLightningTest` will never intercept any HTLCs because there is no
        // lightning connection, so instead we just create a stream that blocks
        // until the task group is shutdown.
        let stream: BoxStream<'a, HtlcResult> = Box::pin(stream! {
            shutdown_receiver.await;
            if let Some(htlc_result) = self.receiver.recv().await {
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
}
