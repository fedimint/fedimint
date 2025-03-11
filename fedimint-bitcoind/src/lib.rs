#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use std::{env, iter};

use anyhow::{Context, Result};
use bitcoin::{Block, BlockHash, Network, ScriptBuf, Transaction, Txid};
use fedimint_core::envs::{
    BitcoinRpcConfig, FM_BITCOIN_POLLING_INTERVAL_SECS_ENV, FM_FORCE_BITCOIN_RPC_KIND_ENV,
    FM_FORCE_BITCOIN_RPC_URL_ENV, FM_WALLET_FEERATE_SOURCES_ENV, is_running_in_test_env,
};
use fedimint_core::task::TaskGroup;
use fedimint_core::time::now;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::{FmtCompact as _, FmtCompactAnyhow, SafeUrl, get_median};
use fedimint_core::{Feerate, apply, async_trait_maybe_send, dyn_newtype_define};
use fedimint_logging::{LOG_BITCOIND, LOG_CORE};
use feerate_source::{FeeRateSource, FetchJson};
use tokio::time::Interval;
use tracing::{debug, trace, warn};

#[cfg(feature = "bitcoincore-rpc")]
pub mod bitcoincore;
#[cfg(feature = "esplora-client")]
mod esplora;
mod feerate_source;

pub mod shared;

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

    async fn get_block(&self, block_hash: &BlockHash) -> Result<Block>;

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

    /// If a transaction is included in a block, returns the block height.
    /// Note: calling this method with bitcoind as a backend must first call
    /// `watch_script_history` or run bitcoind with txindex enabled.
    async fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u64>>;

    /// Check if a transaction is included in a block
    async fn is_tx_in_block(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
        block_height: u64,
    ) -> Result<bool>;

    /// Watches for a script and returns any transactions associated with it
    ///
    /// Should be called at least prior to transactions being submitted or
    /// watching may not occur on backends that need it
    /// TODO: bitcoind backend is broken
    /// `<https://github.com/fedimint/fedimint/issues/5329>`
    async fn watch_script_history(&self, script: &ScriptBuf) -> Result<()>;

    /// Get script transaction history
    ///
    /// Note: should call `watch_script_history` at least once, before calling
    /// this.
    async fn get_script_history(&self, script: &ScriptBuf) -> Result<Vec<Transaction>>;

    /// Returns a proof that a tx is included in the bitcoin blockchain
    async fn get_txout_proof(&self, txid: Txid) -> Result<TxOutProof>;

    /// Returns the node's estimated chain sync percentage as a float between
    /// 0.0 and 1.0, or `None` if the node doesn't support this feature.
    async fn get_sync_percentage(&self) -> Result<Option<f64>>;

    /// Returns the Bitcoin RPC config
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig;
}

dyn_newtype_define! {
    #[derive(Clone)]
    pub DynBitcoindRpc(Arc<IBitcoindRpc>)
}

impl DynBitcoindRpc {
    /// Spawns a background task that queries the block count
    /// periodically and sends over the returned channel.
    pub fn spawn_block_count_update_task(
        self,
        task_group: &TaskGroup,
        on_update: impl Fn(u64) + Send + Sync + 'static,
    ) {
        let mut desired_interval = get_bitcoin_polling_interval();

        // Note: atomic only to workaround Send+Sync async closure limitation
        let last_block_count = AtomicU64::new(0);

        task_group.spawn_cancellable("block count background task", {
            async move {
                trace!(target: LOG_BITCOIND, "Fetching block count from bitcoind");

                let update_block_count = || async {
                    let res = self
                        .get_block_count()
                        .await;

                    match res {
                        Ok(block_count) => {
                            if last_block_count.load(Ordering::SeqCst) != block_count {
                                on_update(block_count);
                                last_block_count.store(block_count, Ordering::SeqCst);
                            }
                        },
                        Err(err) => {
                            warn!(target: LOG_BITCOIND, err = %err.fmt_compact_anyhow(), "Unable to get block count from the node");
                        }
                    }
                };

                loop {
                    let start = now();
                    update_block_count().await;
                    let duration = now().duration_since(start).unwrap_or_default();
                    if Duration::from_secs(10) < duration {
                        warn!(target: LOG_BITCOIND, duration_secs=duration.as_secs(), "Updating block count from bitcoind slow");
                    }
                    desired_interval.tick().await;
                }
            }
        });
    }

    /// Spawns a background task that queries the feerate periodically and sends
    /// over the returned channel.
    pub fn spawn_fee_rate_update_task(
        self,
        task_group: &TaskGroup,
        network: Network,
        confirmation_target: u16,
        on_update: impl Fn(Feerate) + Send + Sync + 'static,
    ) -> anyhow::Result<()> {
        let sources = std::env::var(FM_WALLET_FEERATE_SOURCES_ENV)
            .unwrap_or_else(|_| match network {
                Network::Bitcoin => "https://mempool.space/api/v1/fees/recommended#.hourFee;https://blockstream.info/api/fee-estimates#.\"1\"".to_owned(),
                _ => String::new(),
            })
            .split(';')
            .filter(|s| !s.is_empty())
            .map(|s| Ok(Box::new(FetchJson::from_str(s)?) as Box<dyn FeeRateSource>))
            .chain(iter::once(Ok(
                Box::new(self.clone()) as Box<dyn FeeRateSource>
            )))
            .collect::<anyhow::Result<Vec<Box<dyn FeeRateSource>>>>()?;
        let feerates = Arc::new(std::sync::Mutex::new(vec![None; sources.len()]));

        let mut desired_interval = get_bitcoin_polling_interval();

        task_group.spawn_cancellable("feerate background task", async move {
            trace!(target: LOG_BITCOIND, "Fetching feerate from sources");

            // Note: atomic only to workaround Send+Sync async closure limitation
            let last_feerate = AtomicU64::new(0);

            let update_fee_rate = || async {
                trace!(target: LOG_BITCOIND, "Updating bitcoin fee rate");

                let feerates_new = futures::future::join_all(sources.iter().map(|s| async { (s.name(), s.fetch(confirmation_target).await) } )).await;

                let mut feerates = feerates.lock().expect("lock poisoned");
                for (i, (name, res)) in feerates_new.into_iter().enumerate() {
                    match res {
                        Ok(ok) => feerates[i] = Some(ok),
                        Err(err) => {
                            // Regtest node never returns fee rate, so no point spamming about it
                            if !is_running_in_test_env() {
                                warn!(target: LOG_BITCOIND, err = %err.fmt_compact_anyhow(), %name, "Error getting feerate from source");
                            }
                        },
                    }
                }

                let mut available_feerates : Vec<_> = feerates.iter().filter_map(Clone::clone).map(|r| r.sats_per_kvb).collect();

                available_feerates.sort_unstable();

                if let Some(feerate) = get_median(&available_feerates) {
                    if feerate != last_feerate.load(Ordering::SeqCst) {
                        on_update(Feerate { sats_per_kvb: feerate });
                        last_feerate.store(feerate, Ordering::SeqCst);
                    }
                } else {
                    // During tests (regtest) we never get any real feerate, so no point spamming about it
                    if !is_running_in_test_env() {
                        warn!(target: LOG_BITCOIND, "Unable to calculate any fee rate");
                    }
                }
            };

            loop {
                let start = now();
                update_fee_rate().await;
                let duration = now().duration_since(start).unwrap_or_default();
                if Duration::from_secs(10) < duration {
                    warn!(target: LOG_BITCOIND, duration_secs=duration.as_secs(), "Updating feerate from bitcoind slow");
                }
                desired_interval.tick().await;
            }
        });

        Ok(())
    }
}

fn get_bitcoin_polling_interval() -> Interval {
    fn get_bitcoin_polling_period() -> Duration {
        if let Ok(s) = env::var(FM_BITCOIN_POLLING_INTERVAL_SECS_ENV) {
            use std::str::FromStr;
            match u64::from_str(&s) {
                Ok(secs) => return Duration::from_secs(secs),
                Err(err) => {
                    warn!(
                        target: LOG_BITCOIND,
                        err = %err.fmt_compact(),
                        env = FM_BITCOIN_POLLING_INTERVAL_SECS_ENV,
                        "Could not parse env variable"
                    );
                }
            }
        };
        if is_running_in_test_env() {
            // In devimint, the setup is blocked by detecting block height changes,
            // and polling more often is not an issue.
            debug!(target: LOG_BITCOIND, "Running in devimint, using fast node polling");
            Duration::from_millis(100)
        } else {
            Duration::from_secs(60)
        }
    }
    tokio::time::interval(get_bitcoin_polling_period())
}
