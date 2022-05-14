use std::convert::TryInto;

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
                msatoshi: None,
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
