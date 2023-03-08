use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use bitcoin::secp256k1;
use ln_gateway::gatewaylnrpc::{
    CompleteHtlcsRequest, CompleteHtlcsResponse, GetRouteHintsResponse, PayInvoiceRequest,
    PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
};
use ln_gateway::lnrpc_client::{DynLnRpcClient, HtlcStream, ILnRpcClient};
use ln_gateway::GatewayError;
use tokio::sync::Mutex;

/// A proxy for the underlying LnRpc which can be used to add behavoir to it
/// using the "Decorator pattern"
#[derive(Debug, Clone)]
pub struct LnRpcAdapter {
    /// The actual `ILnRpcClient` that we add behavior to.
    client: DynLnRpcClient,
    /// A pair of <PayInvoiceRequest> and <Count> where client.pay() will fail
    /// <Count> times for each <String> (bolt11 invoice)
    fail_invoices: Arc<Mutex<HashMap<String, u8>>>,
}

impl LnRpcAdapter {
    pub fn new(client: DynLnRpcClient) -> Self {
        let fail_invoices = Arc::new(Mutex::new(HashMap::new()));

        LnRpcAdapter {
            client,
            fail_invoices,
        }
    }

    /// Register <invoice> to fail <times> before (attempt) succeeding. The
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
    async fn node_pubkey(&self) -> anyhow::Result<secp256k1::PublicKey> {
        self.client.node_pubkey().await
    }

    async fn routehints(&self) -> ln_gateway::Result<GetRouteHintsResponse> {
        self.client.routehints().await
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
        self.client.pay(invoice).await
    }

    async fn subscribe_htlcs<'a>(
        &self,
        subscription: SubscribeInterceptHtlcsRequest,
    ) -> ln_gateway::Result<HtlcStream<'a>> {
        self.client.subscribe_htlcs(subscription).await
    }

    async fn complete_htlc(
        &self,
        complete: CompleteHtlcsRequest,
    ) -> ln_gateway::Result<CompleteHtlcsResponse> {
        self.client.complete_htlc(complete).await
    }
}
