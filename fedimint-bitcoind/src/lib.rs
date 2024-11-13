#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]

use std::collections::BTreeMap;
use std::env;
use std::fmt::Debug;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::Context;
pub use anyhow::Result;
use fedimint_core::bitcoin_rpc::DynBitcoindRpc;
use fedimint_core::dyn_newtype_define;
use fedimint_core::envs::{
    BitcoinRpcConfig, FM_FORCE_BITCOIN_RPC_KIND_ENV, FM_FORCE_BITCOIN_RPC_URL_ENV,
};
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_CORE;
use tracing::debug;

#[cfg(feature = "bitcoincore-rpc")]
pub mod bitcoincore;
#[cfg(feature = "esplora-client")]
mod esplora;

// <https://blockstream.info/api/block-height/0>
const MAINNET_GENESIS_BLOCK_HASH: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
// <https://blockstream.info/testnet/api/block-height/0>
const TESTNET_GENESIS_BLOCK_HASH: &str =
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
// <https://mempool.space/signet/api/block-height/0>
const SIGNET_GENESIS_BLOCK_HASH: &str =
    "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
// See <https://bitcoin.stackexchange.com/questions/122778/is-the-regtest-genesis-hash-always-the-same-or-not>
// <https://github.com/bitcoin/bitcoin/blob/d82283950f5ff3b2116e705f931c6e89e5fdd0be/src/kernel/chainparams.cpp#L478>
const REGTEST_GENESIS_BLOCK_HASH: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

/// Global factories for creating bitcoin RPCs
static BITCOIN_RPC_REGISTRY: LazyLock<Mutex<BTreeMap<String, DynBitcoindRpcFactory>>> =
    LazyLock::new(|| {
        Mutex::new(BTreeMap::from([
            #[cfg(feature = "esplora-client")]
            ("esplora".to_string(), esplora::EsploraFactory.into()),
            #[cfg(feature = "bitcoincore-rpc")]
            ("bitcoind".to_string(), bitcoincore::BitcoindFactory.into()),
        ]))
    });

/// Create a bitcoin RPC of a given kind
pub fn create_bitcoind(config: &BitcoinRpcConfig) -> Result<DynBitcoindRpc> {
    let registry = BITCOIN_RPC_REGISTRY.lock().expect("lock poisoned");

    let kind = env::var(FM_FORCE_BITCOIN_RPC_KIND_ENV)
        .ok()
        .unwrap_or_else(|| config.kind.clone());
    let url = env::var(FM_FORCE_BITCOIN_RPC_URL_ENV)
        .ok()
        .map(|s| SafeUrl::parse(&s))
        .transpose()?
        .unwrap_or_else(|| config.url.clone());
    debug!(target: LOG_CORE, %kind, %url, "Starting bitcoin rpc");
    let maybe_factory = registry.get(&kind);
    let factory = maybe_factory.with_context(|| {
        anyhow::anyhow!(
            "{} rpc not registered, available options: {:?}",
            config.kind,
            registry.keys()
        )
    })?;
    factory.create_connection(&url)
}

/// Register a new factory for creating bitcoin RPCs
pub fn register_bitcoind(kind: String, factory: DynBitcoindRpcFactory) {
    let mut registry = BITCOIN_RPC_REGISTRY.lock().expect("lock poisoned");
    registry.insert(kind, factory);
}

/// Trait for creating new bitcoin RPC clients
pub trait IBitcoindRpcFactory: Debug + Send + Sync {
    /// Creates a new bitcoin RPC client connection
    fn create_connection(&self, url: &SafeUrl) -> Result<DynBitcoindRpc>;
}

dyn_newtype_define! {
    #[derive(Clone)]
    pub DynBitcoindRpcFactory(Arc<IBitcoindRpcFactory>)
}
