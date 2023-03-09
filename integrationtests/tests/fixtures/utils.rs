use std::collections::HashMap;
use std::sync::Arc;

use anyhow::bail;
use async_trait::async_trait;
use bitcoin::secp256k1;
use fedimint_ln_client::contracts::Preimage;
use fedimint_ln_client::route_hints::RouteHint;
use lightning_invoice::Invoice;
use ln_gateway::gatewaylnrpc::{
    CompleteHtlcsRequest, CompleteHtlcsResponse, PayInvoiceRequest, SubscribeInterceptHtlcsRequest,
};
use ln_gateway::lnrpc_client::{DynLnRpcClient, HtlcStream, ILnRpcClient};
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

    async fn route_hints(&self) -> anyhow::Result<Vec<RouteHint>> {
        self.client.route_hints().await
    }

    async fn pay(
        &self,
        invoice: &Invoice,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> anyhow::Result<Preimage> {
        let bolt11 = invoice.to_string();
        self.fail_invoices
            .lock()
            .await
            .entry(bolt11.clone())
            .and_modify(|counter| {
                *counter -= 1;
            });
        if let Some(counter) = self.fail_invoices.lock().await.get(&bolt11) {
            if *counter > 0 {
                bail!("expected test error");
            }
        }
        self.fail_invoices.lock().await.remove(&bolt11);
        self.client.pay(invoice, max_delay, max_fee_percent).await
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
