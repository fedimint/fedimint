use async_trait::async_trait;
use clap::ValueEnum;
use fedimint_core::Amount;
use lightning_invoice::Invoice;
use ln_gateway::lnrpc_client::ILnRpcClient;

pub mod mock;
pub mod real;

#[async_trait]
pub trait LightningTest: ILnRpcClient {
    /// Creates invoice from a non-gateway LN node
    async fn invoice(
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
pub enum LightningNodeType {
    Cln,
    Lnd,
}

impl ToString for LightningNodeType {
    fn to_string(&self) -> String {
        match self {
            LightningNodeType::Cln => "cln".to_string(),
            LightningNodeType::Lnd => "lnd".to_string(),
        }
    }
}
