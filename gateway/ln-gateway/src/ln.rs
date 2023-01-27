use async_trait::async_trait;
use fedimint_server::modules::ln::contracts::Preimage;
use fedimint_server::modules::ln::route_hints::RouteHint;
use secp256k1::PublicKey;

#[async_trait]
pub trait LnRpc: Send + Sync + 'static {
    /// Get the public key of the lightning node
    async fn pubkey(&self) -> Result<PublicKey, LightningError>;

    /// Attempt to pay an invoice and block till it succeeds, fails or times out
    async fn pay(
        &self,
        invoice: lightning_invoice::Invoice,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<Preimage, LightningError>;

    /// List peer channels that should be used as route hints in invoices
    async fn route_hints(&self) -> Result<Vec<RouteHint>, anyhow::Error>;
}

#[derive(Debug)]
pub struct LightningError(pub Option<i32>);
