use async_trait::async_trait;
use clap::ValueEnum;
use fedimint_core::Amount;
use lightning_invoice::Invoice;

pub mod mock;
pub mod real;

#[async_trait]
pub trait LightningTest {
    /// Creates invoice from a non-gateway LN node
    async fn invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Invoice>;

    /// Creates invoice from a non-gateway LN node
    async fn invalid_invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Invoice>;

    /// Returns the amount that the gateway LN node has sent
    async fn amount_sent(&self) -> Amount;

    /// Is this a LN instance shared with other tests
    fn is_shared(&self) -> bool;
}

#[derive(ValueEnum, Clone, Debug)]
pub enum GatewayNode {
    Cln,
    Lnd,
}

impl ToString for GatewayNode {
    fn to_string(&self) -> String {
        match self {
            GatewayNode::Cln => "cln".to_string(),
            GatewayNode::Lnd => "lnd".to_string(),
        }
    }
}
