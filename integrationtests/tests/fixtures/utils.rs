use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use fedimint_ln::contracts::Preimage;
use fedimint_ln::route_hints::RouteHint;
use ln_gateway::ln::{LightningError, LnRpc};
use tokio::sync::Mutex;

/// A proxy for the underlying LnRpc which can be used to add behavoir to it using the "Decorator pattern"
pub struct LnRpcAdapter {
    /// The actual LnRpc that we add behavior to.
    client: Box<dyn LnRpc>,
    /// A pair of <Invoice> and <Count> where client.pay() will fail <Count> times for each <Invoice>
    fail_invoices: Arc<Mutex<HashMap<lightning_invoice::Invoice, u8>>>,
}

impl LnRpcAdapter {
    pub fn new(client: Box<dyn LnRpc>) -> Self {
        let fail_invoices = Arc::new(Mutex::new(HashMap::new()));

        LnRpcAdapter {
            client,
            fail_invoices,
        }
    }

    /// Register <invoice> to fail <times> before (attempt) succeeding. The invoice will be dropped from the HashMap after succeeding
    #[allow(dead_code)]
    pub async fn fail_invoice(&self, invoice: lightning_invoice::Invoice, times: u8) {
        self.fail_invoices.lock().await.insert(invoice, times + 1);
    }
}

#[async_trait]
impl LnRpc for LnRpcAdapter {
    async fn pubkey(&self) -> Result<PublicKey, LightningError> {
        self.client.pubkey().await
    }

    async fn pay(
        &self,
        invoice: lightning_invoice::Invoice,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<Preimage, LightningError> {
        self.fail_invoices
            .lock()
            .await
            .entry(invoice.clone())
            .and_modify(|counter| {
                *counter -= 1;
            });
        if let Some(counter) = self.fail_invoices.lock().await.get(&invoice) {
            if *counter > 0 {
                return Err(LightningError(None));
            }
        }
        self.fail_invoices.lock().await.remove(&invoice);
        self.client.pay(invoice, max_delay, max_fee_percent).await
    }

    async fn route_hints(&self) -> Result<Vec<RouteHint>, Error> {
        Ok(vec![])
    }
}
