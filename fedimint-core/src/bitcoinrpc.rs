use std::env;

use fedimint_derive::{Decodable, Encodable};
use jsonrpsee_core::Serialize;
use serde::Deserialize;
use url::Url;

/// Env var for bitcoin RPC kind
pub const FM_BITCOIN_RPC_KIND: &str = "FM_BITCOIN_RPC_KIND";
/// Env var for bitcoin URL
pub const FM_BITCOIN_RPC_URL: &str = "FM_BITCOIN_RPC_URL";

/// Configuration for the bitcoin RPC
#[derive(Debug, Clone, Serialize, Deserialize, Decodable, Encodable)]
pub struct BitcoinRpcConfig {
    pub kind: String,
    pub url: Url,
}

impl BitcoinRpcConfig {
    pub fn from_env_vars() -> anyhow::Result<Self> {
        Ok(Self {
            kind: env::var(FM_BITCOIN_RPC_KIND).map_err(anyhow::Error::from)?,
            url: env::var(FM_BITCOIN_RPC_URL)
                .map_err(anyhow::Error::from)?
                .parse()
                .map_err(anyhow::Error::from)?,
        })
    }
}
