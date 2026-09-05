#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]

pub mod error;
pub mod metrics;

use std::env;
use std::fmt::Debug;
use std::sync::Arc;

use bitcoin::{ScriptBuf, Transaction, Txid};
use esplora_client::{AsyncClient, Builder};
use fedimint_core::envs::FM_FORCE_BITCOIN_RPC_URL_ENV;
use fedimint_core::time::now;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::{FmtCompactResult as _, SafeUrl};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_BITCOIND;
use fedimint_metrics::HistogramExt as _;
use tracing::trace;

pub use crate::error::BitcoinRpcError;
use crate::metrics::{BITCOIND_RPC_DURATION_SECONDS, BITCOIND_RPC_REQUESTS_TOTAL};

const ESPLORA_CLIENT_TIMEOUT_SECONDS: u64 = 60;

#[cfg(feature = "bitcoincore")]
pub mod bitcoincore;

#[derive(Debug, Clone)]
pub struct BlockchainInfo {
    pub block_height: u64,
    pub synced: bool,
}

pub fn create_esplora_rpc(url: &SafeUrl) -> Result<DynBitcoindRpc, BitcoinRpcError> {
    let url = match env::var(FM_FORCE_BITCOIN_RPC_URL_ENV).ok() {
        // The raw value may carry credentials, so the error names the variable instead.
        Some(s) => SafeUrl::parse(&s).map_err(|source| BitcoinRpcError::InvalidUrl {
            url: format!("${FM_FORCE_BITCOIN_RPC_URL_ENV}"),
            source: Box::new(source),
        })?,
        None => url.clone(),
    };

    Ok(EsploraClient::new(&url)?.into_dyn())
}

pub type DynBitcoindRpc = Arc<dyn IBitcoindRpc + Send + Sync>;

/// Trait that allows interacting with the Bitcoin blockchain
///
/// Functions may panic if the bitcoind node is not reachable.
#[apply(async_trait_maybe_send!)]
pub trait IBitcoindRpc: Debug + Send + Sync + 'static {
    /// If a transaction is included in a block, returns the block height.
    async fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u64>, BitcoinRpcError>;

    /// Watches for a script and returns any transaction associated with it
    async fn watch_script_history(&self, script: &ScriptBuf) -> Result<(), BitcoinRpcError>;

    /// Get script transaction history
    async fn get_script_history(
        &self,
        script: &ScriptBuf,
    ) -> Result<Vec<Transaction>, BitcoinRpcError>;

    /// Returns a proof that a tx is included in the bitcoin blockchain
    async fn get_txout_proof(&self, txid: Txid) -> Result<TxOutProof, BitcoinRpcError>;

    /// Returns `BlockchainInfo` which contains a subset of info about the chain
    /// data source.
    async fn get_info(&self) -> Result<BlockchainInfo, BitcoinRpcError>;

    fn into_dyn(self) -> DynBitcoindRpc
    where
        Self: Sized,
    {
        Arc::new(self)
    }
}

/// A wrapper around `DynBitcoindRpc` that tracks metrics for each RPC call.
///
/// This wrapper records the duration and success/error status of each
/// Bitcoin RPC call to Prometheus metrics, allowing monitoring of
/// Bitcoin node connectivity and performance.
pub struct BitcoindTracked {
    inner: DynBitcoindRpc,
    name: &'static str,
}

impl std::fmt::Debug for BitcoindTracked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitcoindTracked")
            .field("name", &self.name)
            .field("inner", &self.inner)
            .finish()
    }
}

impl BitcoindTracked {
    /// Wraps a `DynBitcoindRpc` with metrics tracking.
    ///
    /// The `name` parameter is used to distinguish different uses of the
    /// Bitcoin RPC client in metrics (e.g., "wallet-client", "recovery").
    pub fn new(inner: DynBitcoindRpc, name: &'static str) -> Self {
        Self { inner, name }
    }

    fn record_call<T>(&self, method: &str, result: &Result<T, BitcoinRpcError>) {
        let result_label = if result.is_ok() { "success" } else { "error" };
        BITCOIND_RPC_REQUESTS_TOTAL
            .with_label_values(&[method, self.name, result_label])
            .inc();
    }
}

macro_rules! tracked_call {
    ($self:ident, $method:expr, $call:expr) => {{
        trace!(
            target: LOG_BITCOIND,
            method = $method,
            name = $self.name,
            "starting bitcoind rpc"
        );
        let start = now();
        let timer = BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&[$method, $self.name])
            .start_timer_ext();
        let result = $call;
        timer.observe_duration();
        $self.record_call($method, &result);
        let duration_ms = now()
            .duration_since(start)
            .unwrap_or_default()
            .as_secs_f64()
            * 1000.0;
        trace!(
            target: LOG_BITCOIND,
            method = $method,
            name = $self.name,
            duration_ms,
            error = %result.fmt_compact_result(),
            "completed bitcoind rpc"
        );
        result
    }};
}

#[apply(async_trait_maybe_send!)]
impl IBitcoindRpc for BitcoindTracked {
    async fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u64>, BitcoinRpcError> {
        tracked_call!(
            self,
            "get_tx_block_height",
            self.inner.get_tx_block_height(txid).await
        )
    }

    async fn watch_script_history(&self, script: &ScriptBuf) -> Result<(), BitcoinRpcError> {
        tracked_call!(
            self,
            "watch_script_history",
            self.inner.watch_script_history(script).await
        )
    }

    async fn get_script_history(
        &self,
        script: &ScriptBuf,
    ) -> Result<Vec<Transaction>, BitcoinRpcError> {
        tracked_call!(
            self,
            "get_script_history",
            self.inner.get_script_history(script).await
        )
    }

    async fn get_txout_proof(&self, txid: Txid) -> Result<TxOutProof, BitcoinRpcError> {
        tracked_call!(
            self,
            "get_txout_proof",
            self.inner.get_txout_proof(txid).await
        )
    }

    async fn get_info(&self) -> Result<BlockchainInfo, BitcoinRpcError> {
        tracked_call!(self, "get_info", self.inner.get_info().await)
    }
}

#[derive(Debug)]
pub struct EsploraClient {
    client: AsyncClient,
}

impl EsploraClient {
    pub fn new(url: &SafeUrl) -> Result<Self, BitcoinRpcError> {
        let client = Builder::new(url.as_str().trim_end_matches('/'))
            .timeout(ESPLORA_CLIENT_TIMEOUT_SECONDS)
            .build_async()
            .map_err(|source| BitcoinRpcError::InvalidUrl {
                url: url.to_string(),
                source: Box::new(source),
            })?;

        Ok(Self { client })
    }
}

#[apply(async_trait_maybe_send!)]
impl IBitcoindRpc for EsploraClient {
    async fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u64>, BitcoinRpcError> {
        Ok(self
            .client
            .get_tx_status(txid)
            .await
            .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?
            .block_height
            .map(u64::from))
    }

    async fn watch_script_history(&self, _: &ScriptBuf) -> Result<(), BitcoinRpcError> {
        // no watching needed, has all the history already
        Ok(())
    }

    async fn get_script_history(
        &self,
        script: &ScriptBuf,
    ) -> Result<Vec<bitcoin::Transaction>, BitcoinRpcError> {
        const MAX_TX_HISTORY: usize = 1000;

        let mut transactions = Vec::new();
        let mut last_seen: Option<Txid> = None;

        loop {
            let page = self
                .client
                .scripthash_txs(script, last_seen)
                .await
                .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?;

            if page.is_empty() {
                break;
            }

            for tx in &page {
                transactions.push(tx.to_tx());
            }

            if transactions.len() >= MAX_TX_HISTORY {
                return Err(BitcoinRpcError::ScriptHistoryTooLong {
                    max: MAX_TX_HISTORY,
                });
            }

            last_seen = Some(page.last().expect("page not empty").txid);
        }

        Ok(transactions)
    }

    async fn get_txout_proof(&self, txid: Txid) -> Result<TxOutProof, BitcoinRpcError> {
        let proof = self
            .client
            .get_merkle_block(&txid)
            .await
            .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?
            .ok_or(BitcoinRpcError::ProofNotFound { txid })?;

        Ok(TxOutProof {
            block_header: proof.header,
            merkle_proof: proof.txn,
        })
    }

    async fn get_info(&self) -> Result<BlockchainInfo, BitcoinRpcError> {
        let height = self
            .client
            .get_height()
            .await
            .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?;
        Ok(BlockchainInfo {
            block_height: u64::from(height),
            synced: true,
        })
    }
}
