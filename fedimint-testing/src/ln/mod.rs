use async_trait::async_trait;
use fedimint_core::Amount;
use lightning_invoice::Invoice;

pub mod fixtures;

#[async_trait]
pub trait LightningTest {
    /// Creates invoice from a non-gateway LN node
    async fn invoice(&self, amount: Amount, expiry_time: Option<u64>) -> Invoice;

    /// Returns the amount that the gateway LN node has sent
    async fn amount_sent(&self) -> Amount;

    /// Is this a LN instance shared with other tests
    fn is_shared(&self) -> bool;
}
