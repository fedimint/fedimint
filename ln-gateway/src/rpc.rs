use async_trait::async_trait;
use fedimint_server::modules::ln::contracts::Preimage;

use crate::GatewayRequestTrait;

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

#[async_trait]
pub trait GatewayRpcSender: Send + Sync + 'static {
    async fn send<R: GatewayRequestTrait>(&self, message: R) -> Result<R::Response, anyhow::Error>;
}

#[async_trait]
pub trait GatewayRpcReceiver {
    async fn receive(&mut self) -> ();
}
