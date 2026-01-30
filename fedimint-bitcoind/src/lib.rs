#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]

pub mod metrics;

use std::env;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Result, format_err};
use bitcoin::{ScriptBuf, Transaction, Txid};
use esplora_client::{AsyncClient, Builder};
use fedimint_core::envs::FM_FORCE_BITCOIN_RPC_URL_ENV;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_metrics::HistogramExt as _;

use crate::metrics::{BITCOIND_RPC_DURATION_SECONDS, BITCOIND_RPC_REQUESTS_TOTAL};

#[cfg(feature = "bitcoincore")]
pub mod bitcoincore;

#[derive(Debug, Clone)]
pub struct BlockchainInfo {
    pub block_height: u64,
    pub synced: bool,
}

pub fn create_esplora_rpc(url: &SafeUrl) -> Result<DynBitcoindRpc> {
    let url = env::var(FM_FORCE_BITCOIN_RPC_URL_ENV)
        .ok()
        .map(|s| SafeUrl::parse(&s))
        .transpose()?
        .unwrap_or_else(|| url.clone());

    Ok(EsploraClient::new(&url)?.into_dyn())
}

pub type DynBitcoindRpc = Arc<dyn IBitcoindRpc + Send + Sync>;

/// Trait that allows interacting with the Bitcoin blockchain
///
/// Functions may panic if the bitcoind node is not reachable.
#[apply(async_trait_maybe_send!)]
pub trait IBitcoindRpc: Debug + Send + Sync + 'static {
    /// If a transaction is included in a block, returns the block height.
    async fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u64>>;

    /// Watches for a script and returns any transaction associated with it
    async fn watch_script_history(&self, script: &ScriptBuf) -> Result<()>;

    /// Get script transaction history
    async fn get_script_history(&self, script: &ScriptBuf) -> Result<Vec<Transaction>>;

    /// Returns a proof that a tx is included in the bitcoin blockchain
    async fn get_txout_proof(&self, txid: Txid) -> Result<TxOutProof>;

    /// Returns `BlockchainInfo` which contains a subset of info about the chain
    /// data source.
    async fn get_info(&self) -> Result<BlockchainInfo>;

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

    fn record_call<T>(&self, method: &str, result: &Result<T>) {
        let result_label = if result.is_ok() { "success" } else { "error" };
        BITCOIND_RPC_REQUESTS_TOTAL
            .with_label_values(&[method, self.name, result_label])
            .inc();
    }
}

#[apply(async_trait_maybe_send!)]
impl IBitcoindRpc for BitcoindTracked {
    async fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u64>> {
        let timer = BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["get_tx_block_height", self.name])
            .start_timer_ext();
        let result = self.inner.get_tx_block_height(txid).await;
        timer.observe_duration();
        self.record_call("get_tx_block_height", &result);
        result
    }

    async fn watch_script_history(&self, script: &ScriptBuf) -> Result<()> {
        let timer = BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["watch_script_history", self.name])
            .start_timer_ext();
        let result = self.inner.watch_script_history(script).await;
        timer.observe_duration();
        self.record_call("watch_script_history", &result);
        result
    }

    async fn get_script_history(&self, script: &ScriptBuf) -> Result<Vec<Transaction>> {
        let timer = BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["get_script_history", self.name])
            .start_timer_ext();
        let result = self.inner.get_script_history(script).await;
        timer.observe_duration();
        self.record_call("get_script_history", &result);
        result
    }

    async fn get_txout_proof(&self, txid: Txid) -> Result<TxOutProof> {
        let timer = BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["get_txout_proof", self.name])
            .start_timer_ext();
        let result = self.inner.get_txout_proof(txid).await;
        timer.observe_duration();
        self.record_call("get_txout_proof", &result);
        result
    }

    async fn get_info(&self) -> Result<BlockchainInfo> {
        let timer = BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["get_info", self.name])
            .start_timer_ext();
        let result = self.inner.get_info().await;
        timer.observe_duration();
        self.record_call("get_info", &result);
        result
    }
}

#[derive(Debug)]
pub struct EsploraClient {
    client: AsyncClient,
}

impl EsploraClient {
    pub fn new(url: &SafeUrl) -> anyhow::Result<Self> {
        Ok(Self {
            // URL needs to have any trailing path including '/' removed
            client: Builder::new(url.as_str().trim_end_matches('/')).build_async()?,
        })
    }
}

#[apply(async_trait_maybe_send!)]
impl IBitcoindRpc for EsploraClient {
    async fn get_tx_block_height(&self, txid: &Txid) -> anyhow::Result<Option<u64>> {
        Ok(self
            .client
            .get_tx_status(txid)
            .await?
            .block_height
            .map(u64::from))
    }

    async fn watch_script_history(&self, _: &ScriptBuf) -> anyhow::Result<()> {
        // no watching needed, has all the history already
        Ok(())
    }

    async fn get_script_history(
        &self,
        script: &ScriptBuf,
    ) -> anyhow::Result<Vec<bitcoin::Transaction>> {
        const MAX_TX_HISTORY: usize = 1000;

        let mut transactions = Vec::new();
        let mut last_seen: Option<Txid> = None;

        loop {
            let page = self.client.scripthash_txs(script, last_seen).await?;

            if page.is_empty() {
                break;
            }

            for tx in &page {
                transactions.push(tx.to_tx());
            }

            if transactions.len() >= MAX_TX_HISTORY {
                return Err(format_err!(
                    "Script history exceeds maximum limit of {}",
                    MAX_TX_HISTORY
                ));
            }

            last_seen = Some(page.last().expect("page not empty").txid);
        }

        Ok(transactions)
    }

    async fn get_txout_proof(&self, txid: Txid) -> anyhow::Result<TxOutProof> {
        let proof = self
            .client
            .get_merkle_block(&txid)
            .await?
            .ok_or(format_err!("No merkle proof found"))?;

        Ok(TxOutProof {
            block_header: proof.header,
            merkle_proof: proof.txn,
        })
    }

    async fn get_info(&self) -> anyhow::Result<BlockchainInfo> {
        let height = self.client.get_height().await?;
        Ok(BlockchainInfo {
            block_height: u64::from(height),
            synced: true,
        })
    }
}
