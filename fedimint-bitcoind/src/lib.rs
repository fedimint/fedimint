use std::cmp::min;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
pub use anyhow::Result;
use bitcoin::{BlockHash, Network, Script, Transaction, Txid};
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::fmt_utils::OptStacktrace;
use fedimint_core::task::TaskHandle;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, dyn_newtype_define, Feerate};
use fedimint_logging::LOG_BLOCKCHAIN;
use lazy_static::lazy_static;
use tracing::info;

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

lazy_static! {
    /// Global factories for creating bitcoin RPCs
    static ref BITCOIN_RPC_REGISTRY: Mutex<BTreeMap<String, DynBitcoindRpcFactory>> =
        Mutex::new(BTreeMap::from([
            #[cfg(feature = "esplora-client")]
            ("esplora".to_string(), esplora::EsploraFactory.into()),
            #[cfg(feature = "electrum-client")]
            ("electrum".to_string(), electrum::ElectrumFactory.into()),
            #[cfg(feature = "bitcoincore-rpc")]
            ("bitcoind".to_string(), bitcoincore::BitcoindFactory.into()),
        ]));
}

/// Create a bitcoin RPC of a given kind
pub fn create_bitcoind(config: &BitcoinRpcConfig, handle: TaskHandle) -> Result<DynBitcoindRpc> {
    let registry = BITCOIN_RPC_REGISTRY.lock().expect("lock poisoned");
    let maybe_factory = registry.get(&config.kind);
    let factory = maybe_factory.with_context(|| {
        anyhow::anyhow!(
            "{} rpc not registered, available options: {:?}",
            config.kind,
            registry.keys()
        )
    })?;
    factory.create_connection(&config.url, handle)
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

/// Trait that allows interacting with the Bitcoin blockchain
///
/// Functions may panic if the bitcoind node is not reachable.
#[apply(async_trait_maybe_send!)]
pub trait IBitcoindRpc: Debug {
    /// Returns the Bitcoin network the node is connected to
    async fn get_network(&self) -> Result<bitcoin::Network>;

    /// Returns the current block count
    async fn get_block_count(&self) -> Result<u64>;

    /// Returns the block hash at a given height
    ///
    /// # Panics
    /// If the node does not know a block for that height. Make sure to only
    /// query blocks of a height less to the one returned by
    /// `Self::get_block_count`.
    ///
    /// While there is a corner case that the blockchain shrinks between these
    /// two calls (through on average heavier blocks on a fork) this is
    /// prevented by only querying hashes for blocks tailing the chain tip
    /// by a certain number of blocks.
    async fn get_block_hash(&self, height: u64) -> Result<BlockHash>;

    /// Estimates the fee rate for a given confirmation target. Make sure that
    /// all federation members use the same algorithm to avoid widely
    /// diverging results. If the node is not ready yet to return a fee rate
    /// estimation this function returns `None`.
    async fn get_fee_rate(&self, confirmation_target: u16) -> Result<Option<Feerate>>;

    /// Submits a transaction to the Bitcoin network
    ///
    /// This operation does not return anything as it never OK to consider its
    /// success as final anyway. The caller should be retrying
    /// broadcast periodically until it confirms the transaction was actually
    /// via other means or decides that is no longer relevant.
    ///
    /// Also - most backends considers brodcasting a tx that is already included
    /// in the blockchain as an error, which breaks idempotency and requires
    /// brittle workarounds just to reliably ignore... just to retry on the
    /// higher level anyway.
    ///
    /// Implementations of this error should log errors for debugging purposes
    /// when it makes sense.
    async fn submit_transaction(&self, transaction: Transaction);

    /// Check if a transaction is included in a block
    async fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u64>>;

    /// Watches for a script and returns any transactions associated with it
    ///
    /// Should be called once prior to transactions being submitted or watching
    /// may not occur
    async fn watch_script_history(&self, script: &Script) -> Result<Vec<Transaction>>;

    /// Returns a proof that a tx is included in the bitcoin blockchain
    async fn get_txout_proof(&self, txid: Txid) -> Result<TxOutProof>;
}

dyn_newtype_define! {
    #[derive(Clone)]
    pub DynBitcoindRpc(Arc<IBitcoindRpc>)
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
                    std::thread::sleep(retry_time);
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

    async fn watch_script_history(&self, script: &Script) -> Result<Vec<Transaction>> {
        self.retry_call(|| async { self.inner.watch_script_history(script).await })
            .await
    }

    async fn get_txout_proof(&self, txid: Txid) -> Result<TxOutProof> {
        self.retry_call(|| async { self.inner.get_txout_proof(txid).await })
            .await
    }
}
