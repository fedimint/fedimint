use async_trait::async_trait;
use fedimint_server::modules::ln::contracts::Preimage;

#[async_trait]
pub trait LnRpc: Send + Sync + 'static {
    /// Attempt to pay an invoice and block till it succeeds, fails or times out
    async fn pay(
        &self,
        invoice: &str,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<Preimage, LightningError>;
}

#[derive(Debug)]
pub struct LightningError(pub Option<i32>);
