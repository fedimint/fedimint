#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]

use std::cmp::min;
use std::collections::BTreeMap;
use std::env;
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use anyhow::Context;
pub use anyhow::Result;
use bitcoin::{BlockHash, Network, ScriptBuf, Transaction, Txid};
use fedimint_core::bitcoin_rpc::{DynBitcoindRpc, IBitcoindRpc};
use fedimint_core::envs::{
    BitcoinRpcConfig, FM_FORCE_BITCOIN_RPC_KIND_ENV, FM_FORCE_BITCOIN_RPC_URL_ENV,
};
use fedimint_core::fmt_utils::OptStacktrace;
use fedimint_core::runtime::sleep;
use fedimint_core::task::TaskHandle;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, dyn_newtype_define, Feerate};
use fedimint_logging::{LOG_BLOCKCHAIN, LOG_CORE};
use tracing::{debug, info};

#[cfg(feature = "bitcoincore-rpc")]
pub mod bitcoincore;
#[cfg(feature = "electrum-client")]
mod electrum;
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
            #[cfg(feature = "electrum-client")]
            ("electrum".to_string(), electrum::ElectrumFactory.into()),
            #[cfg(feature = "bitcoincore-rpc")]
            ("bitcoind".to_string(), bitcoincore::BitcoindFactory.into()),
        ]))
    });

/// Create a bitcoin RPC of a given kind
pub fn create_bitcoind(config: &BitcoinRpcConfig, handle: TaskHandle) -> Result<DynBitcoindRpc> {
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
    factory.create_connection(&url, handle)
}

/// Register a new factory for creating bitcoin RPCs
pub fn register_bitcoind(kind: String, factory: DynBitcoindRpcFactory) {
    let mut registry = BITCOIN_RPC_REGISTRY.lock().expect("lock poisoned");
    registry.insert(kind, factory);
}

/// Trait for creating new bitcoin RPC clients
pub trait IBitcoindRpcFactory: Debug + Send + Sync {
    /// Creates a new bitcoin RPC client connection
    fn create_connection(&self, url: &SafeUrl, handle: TaskHandle) -> Result<DynBitcoindRpc>;
}

dyn_newtype_define! {
    #[derive(Clone)]
    pub DynBitcoindRpcFactory(Arc<IBitcoindRpcFactory>)
}

const RETRY_SLEEP_MIN_MS: Duration = Duration::from_millis(10);
const RETRY_SLEEP_MAX_MS: Duration = Duration::from_millis(5000);

/// Wrapper around [`IBitcoindRpc`] that will retry failed calls
#[derive(Debug)]
pub struct RetryClient<C> {
    inner: C,
    task_handle: TaskHandle,
}

impl<C> RetryClient<C> {
    pub fn new(inner: C, task_handle: TaskHandle) -> Self {
        Self { inner, task_handle }
    }

    /// Retries with an exponential backoff from `RETRY_SLEEP_MIN_MS` to
    /// `RETRY_SLEEP_MAX_MS`
    async fn retry_call<T, F, R>(&self, call_fn: F) -> Result<T>
    where
        F: Fn() -> R,
        R: Future<Output = Result<T>>,
    {
        let mut retry_time = RETRY_SLEEP_MIN_MS;
        let ret = loop {
            match call_fn().await {
                Ok(ret) => {
                    break ret;
                }
                Err(e) => {
                    if self.task_handle.is_shutting_down() {
                        return Err(e);
                    }

                    info!(target: LOG_BLOCKCHAIN, "Bitcoind error {}, retrying", OptStacktrace(e));
                    sleep(retry_time).await;
                    retry_time = min(RETRY_SLEEP_MAX_MS, retry_time * 2);
                }
            }
        };
        Ok(ret)
    }
}

#[apply(async_trait_maybe_send!)]
impl<C> IBitcoindRpc for RetryClient<C>
where
    C: IBitcoindRpc + Sync + Send,
{
    async fn get_network(&self) -> Result<Network> {
        self.retry_call(|| async { self.inner.get_network().await })
            .await
    }

    async fn get_block_count(&self) -> Result<u64> {
        self.retry_call(|| async { self.inner.get_block_count().await })
            .await
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        self.retry_call(|| async { self.inner.get_block_hash(height).await })
            .await
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> Result<Option<Feerate>> {
        self.retry_call(|| async { self.inner.get_fee_rate(confirmation_target).await })
            .await
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        self.inner.submit_transaction(transaction.clone()).await;
    }

    async fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u64>> {
        self.retry_call(|| async { self.inner.get_tx_block_height(txid).await })
            .await
    }

    async fn is_tx_in_block(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
        block_height: u64,
    ) -> Result<bool> {
        self.retry_call(|| async {
            self.inner
                .is_tx_in_block(txid, block_hash, block_height)
                .await
        })
        .await
    }

    async fn watch_script_history(&self, script: &ScriptBuf) -> Result<()> {
        self.retry_call(|| async { self.inner.watch_script_history(script).await })
            .await
    }

    async fn get_script_history(&self, script: &ScriptBuf) -> Result<Vec<Transaction>> {
        self.retry_call(|| async { self.inner.get_script_history(script).await })
            .await
    }

    async fn get_txout_proof(&self, txid: Txid) -> Result<TxOutProof> {
        self.retry_call(|| async { self.inner.get_txout_proof(txid).await })
            .await
    }

    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        self.inner.get_bitcoin_rpc_config()
    }
}
