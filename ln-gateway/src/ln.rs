use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Arc;

use async_trait::async_trait;
use cln_rpc::model::requests::PayRequest;
use tokio::sync::Mutex;
use tracing::{debug, instrument};

#[async_trait]
pub trait LnRpc: Send + Sync + 'static {
    /// Attempt to pay an invoice and block till it succeeds, fails or times out
    async fn pay(
        &self,
        invoice: &str,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<[u8; 32], LightningError>;
}

#[derive(Debug)]
pub struct LightningError(Option<i32>);

#[async_trait]
impl LnRpc for Mutex<cln_rpc::ClnRpc> {
    #[instrument(name = "LnRpc::pay", skip(self))]
    async fn pay(
        &self,
        invoice: &str,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<[u8; 32], LightningError> {
        debug!("Attempting to pay invoice");

        let pay_result = self
            .lock()
            .await
            .call(cln_rpc::Request::Pay(PayRequest {
                bolt11: invoice.to_string(),
                amount_msat: None,
                label: None,
                riskfactor: None,
                maxfeepercent: Some(max_fee_percent),
                retry_for: None,
                maxdelay: Some(max_delay as u16),
                exemptfee: None,
                localofferid: None,
                exclude: None,
                maxfee: None,
                description: None,
            }))
            .await;

        match pay_result {
            Ok(cln_rpc::Response::Pay(pay_success)) => {
                debug!("Successfully paid invoice");
                Ok(pay_success.payment_preimage.to_vec().try_into().unwrap())
            }
            Ok(_) => unreachable!("unexpected response from C-lightning"),
            Err(cln_rpc::RpcError { code, message }) => {
                if let Some(code) = code {
                    debug!(%code, %message, "c-lightning pay returned error");
                } else {
                    debug!(%message, "c-lightning pay returned error");
                }
                Err(LightningError(code))
            }
        }
    }
}

/// Control the behavoir of the LnRpc by exposing the same interface but attach configurations and
/// methods to it.
pub struct LnRpcAdapter {
    ln_client: Box<dyn LnRpc>,
    fail_invoice: Arc<Mutex<HashMap<String, u8>>>,
}

impl LnRpcAdapter {
    pub fn new(ln_client: Box<dyn LnRpc>) -> Self {
        let fail_invoice = Arc::new(Mutex::new(HashMap::new()));

        LnRpcAdapter {
            ln_client,
            fail_invoice,
        }
    }

    /// Tell the LnRpc to fail the payment x-times until succeeding (or trying to succeed in the
    /// case of real LnRpc
    pub async fn fail_invoice(&self, invoice: String, times: u8) {
        self.fail_invoice.lock().await.insert(invoice, times + 1);
    }
}

#[async_trait]
impl LnRpc for LnRpcAdapter {
    async fn pay(
        &self,
        invoice_str: &str,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<[u8; 32], LightningError> {
        self.fail_invoice
            .lock()
            .await
            .entry(invoice_str.to_string())
            .and_modify(|counter| {
                *counter -= 1;
            });
        if let Some(counter) = self.fail_invoice.lock().await.get(invoice_str) {
            if *counter > 0 {
                return Err(LightningError(None));
            }
        }
        self.ln_client
            .pay(invoice_str, max_delay, max_fee_percent)
            .await
    }
}
