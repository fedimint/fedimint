use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bitcoin::{secp256k1::PublicKey, XOnlyPublicKey};
use fedimint_ln::contracts::Preimage;
use ln_gateway::{
    rpc::{
        lnrpc_client::{ILnRpcClient, LnRpcClient},
        HtlcInterceptPayload,
    },
    Result,
};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;

/// A proxy for the underlying LnRpcClient which can be used to add behavoir to it using the "Decorator pattern"
#[derive(Debug)]
pub struct LnRpcClientAdapter {
    /// The actual LnRpc that we add behavior to.
    client: LnRpcClient,
    /// A pair of <Invoice> and <Count> where client.pay() will fail <Count> times for each <Invoice>
    fail_invoices: Arc<Mutex<HashMap<lightning_invoice::Invoice, u8>>>,
}

impl LnRpcClientAdapter {
    pub fn new(client: LnRpcClient) -> Self {
        let fail_invoices = Arc::new(Mutex::new(HashMap::new()));

        LnRpcClientAdapter {
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
impl ILnRpcClient for LnRpcClientAdapter {
    async fn get_pubkey(&self) -> Result<PublicKey> {
        self.client.get_pubkey().await
    }

    async fn pay_invoice(
        &self,
        invoice: lightning_invoice::Invoice,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<Preimage> {
        self.fail_invoices
            .lock()
            .await
            .entry(invoice.clone())
            .and_modify(|counter| {
                *counter -= 1;
            });
        if let Some(counter) = self.fail_invoices.lock().await.get(&invoice) {
            if *counter > 0 {
                return Err(anyhow::anyhow!("Failing invoice").into());
            }
        }
        self.fail_invoices.lock().await.remove(&invoice);
        self.client
            .pay_invoice(invoice, max_delay, max_fee_percent)
            .await
    }

    async fn subscribe_intercept_htlcs(
        &self,
        mint_pub_key: XOnlyPublicKey,
    ) -> Result<Receiver<HtlcInterceptPayload>> {
        self.client.subscribe_intercept_htlcs(mint_pub_key).await
    }
}
