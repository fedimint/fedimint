use std::env;

use anyhow::Context;
use fedimint_derive::{Decodable, Encodable};
use jsonrpsee_core::Serialize;
use serde::Deserialize;
use url::Url;

/// Env var for bitcoin RPC kind
pub const FM_BITCOIN_RPC_KIND: &str = "FM_BITCOIN_RPC_KIND";
/// Env var for bitcoin URL
pub const FM_BITCOIN_RPC_URL: &str = "FM_BITCOIN_RPC_URL";

/// Configuration for the bitcoin RPC
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct BitcoinRpcConfig {
    pub kind: String,
    pub url: Url,
}

impl BitcoinRpcConfig {
    pub fn from_env_vars() -> anyhow::Result<Self> {
        Ok(Self {
            kind: env::var(FM_BITCOIN_RPC_KIND).with_context(|| {
                anyhow::anyhow!("failure looking up env var {FM_BITCOIN_RPC_KIND}")
            })?,
            url: env::var(FM_BITCOIN_RPC_URL)
                .with_context(|| {
                    anyhow::anyhow!("failure looking up env var {FM_BITCOIN_RPC_URL}")
                })?
                .parse()
                .with_context(|| anyhow::anyhow!("failure parsing env var {FM_BITCOIN_RPC_URL}"))?,
        })
    }
}
