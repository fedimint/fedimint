use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_core::task::RwLock;
use ln_gateway::gatewaylnrpc::{
    CompleteHtlcsRequest, CompleteHtlcsResponse, GetNodeInfoResponse, GetRouteHintsResponse,
    PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
};
use ln_gateway::lnrpc_client::{HtlcStream, ILnRpcClient};
use ln_gateway::GatewayError;
use tokio::sync::Mutex;

/// A proxy for the underlying LnRpc which can be used to add behavior to it
/// using the "Decorator pattern"
#[derive(Debug, Clone)]
pub struct LnRpcAdapter {
    /// The actual `ILnRpcClient` that we add behavior to.
    client: Arc<RwLock<dyn ILnRpcClient>>,
    /// A pair of <PayInvoiceRequest> and <Count> where client.pay() will fail
    /// <Count> times for each <String> (bolt11 invoice)
    fail_invoices: Arc<Mutex<HashMap<String, u8>>>,
}

impl LnRpcAdapter {
    pub fn new(client: Arc<RwLock<dyn ILnRpcClient>>) -> Self {
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

    async fn subscribe_htlcs<'a>(
        &self,
        subscription: SubscribeInterceptHtlcsRequest,
    ) -> ln_gateway::Result<HtlcStream<'a>> {
        self.client.read().await.subscribe_htlcs(subscription).await
    }

    async fn complete_htlc(
        &self,
        complete: CompleteHtlcsRequest,
    ) -> ln_gateway::Result<CompleteHtlcsResponse> {
        self.client.read().await.complete_htlc(complete).await
    }
}
