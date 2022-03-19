use async_trait::async_trait;
use clightningrpc::lightningrpc::PayOptions;
use tracing::{debug, trace};

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
pub struct LightningError(i32);

// TODO: switch to https://github.com/ElementsProject/lightning/pull/5010 once ready
#[async_trait]
impl LnRpc for clightningrpc::LightningRPC {
    async fn pay(
        &self,
        invoice: &str,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<[u8; 32], LightningError> {
        debug!("Attempting to pay invoice {}", invoice);
        let pay_result = tokio::task::block_in_place(|| {
            self.pay(
                invoice,
                PayOptions {
                    msatoshi: None,
                    description: None,
                    riskfactor: None,
                    maxfeepercent: Some(max_fee_percent),
                    exemptfee: None,
                    retry_for: None,
                    maxdelay: Some(max_delay),
                },
            )
        });
        match pay_result {
            Ok(pay_success) => {
                debug!("Successfully paid invoice {}", invoice);
                let payment_preimage_str = pay_success.payment_preimage;
                let mut payment_preimage = [0u8; 32];
                hex::decode_to_slice(payment_preimage_str, &mut payment_preimage)
                    .expect("c-lightning returned a malformed preimage");
                Ok(payment_preimage)
            }
            Err(clightningrpc::Error::Rpc(clightningrpc::error::RpcError {
                code,
                message,
                data,
            })) => {
                debug!("c-lightning pay returned error {}: {}", code, message);
                trace!("error data: {:?}", data);
                Err(LightningError(code))
            }
            Err(_) => panic!("C-Lightning had an unexpected error"),
        }
    }
}
