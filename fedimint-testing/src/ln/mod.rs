pub mod fake;
pub mod real;

use async_trait::async_trait;
use fedimint_api::Amount;
use lightning_invoice::Invoice;

#[async_trait]
pub trait LightningTest {
    /// Creates invoice from a non-gateway LN node
    async fn invoice(&self, amount: Amount, expiry_time: Option<u64>) -> Invoice;

    /// Returns the amount that the gateway LN node has sent
    async fn amount_sent(&self) -> Amount;
}
