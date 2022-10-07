use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use fedimint_server::modules::ln::contracts::Preimage;
use secp256k1::PublicKey;

use crate::messaging::GatewayMessageChannel;

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
pub trait LnRpcFactory: Send + Sync + 'static {
    async fn create(
        &self,
        messenger: GatewayMessageChannel,
    ) -> Result<Arc<LnRpcRef>, anyhow::Error>;
}

pub struct LnRpcRef {
    pub ln_rpc: Arc<dyn LnRpc>,
    pub bind_addr: SocketAddr,
    pub pub_key: PublicKey,
    pub work_dir: PathBuf,
}
