use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use fedimint_server::modules::ln::contracts::Preimage;
use secp256k1::PublicKey;
use thiserror::Error;

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
    ) -> Result<Arc<LnRpcConfig>, anyhow::Error>;
}

pub struct LnRpcConfig {
    pub ln_rpc: Arc<dyn LnRpc>,
    pub bind_addr: SocketAddr,
    pub pub_key: PublicKey,
    pub work_dir: PathBuf,
}

/// A standardized staruture for staged initialization of Gateway LnRpc
pub struct GatewayLnRpcConfig {
    factory: Arc<dyn LnRpcFactory>,
    config: Option<Arc<LnRpcConfig>>,
}

impl GatewayLnRpcConfig {
    pub fn new(factory: Arc<dyn LnRpcFactory>) -> Self {
        GatewayLnRpcConfig {
            factory,
            config: None,
        }
    }

    pub async fn init(
        &mut self,
        messenger: GatewayMessageChannel,
    ) -> Result<Arc<LnRpcConfig>, GatewayLnRpcConfigError> {
        match self.factory.create(messenger).await {
            Ok(config) => {
                self.config = Some(config.clone());
                Ok(config)
            }
            Err(e) => Err(GatewayLnRpcConfigError::InstantiationError(e)),
        }
    }

    pub fn config(&self) -> Result<Arc<LnRpcConfig>, GatewayLnRpcConfigError> {
        let config = self
            .config
            .clone()
            .ok_or(GatewayLnRpcConfigError::InstantiationError(
                anyhow::anyhow!("GatewayLnRPC not initialized"),
            ))?;
        Ok(config)
    }
}

#[derive(Debug, Error)]
pub enum GatewayLnRpcConfigError {
    #[error("Instantiation erro: {0:?}")]
    InstantiationError(#[from] anyhow::Error),
}
