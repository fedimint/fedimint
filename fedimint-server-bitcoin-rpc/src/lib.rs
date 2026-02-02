pub mod bitcoind;
pub mod esplora;
pub mod metrics;

use anyhow::Result;
use bitcoin::{BlockHash, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::util::{FmtCompactAnyhow, SafeUrl};
use fedimint_core::{ChainId, Feerate};
use fedimint_logging::LOG_SERVER;
use fedimint_metrics::HistogramExt as _;
use fedimint_server_core::bitcoin_rpc::{DynServerBitcoinRpc, IServerBitcoinRpc};
use tracing::warn;

use crate::bitcoind::BitcoindClient;
use crate::esplora::EsploraClient;
use crate::metrics::{SERVER_BITCOIND_RPC_DURATION_SECONDS, SERVER_BITCOIND_RPC_REQUESTS_TOTAL};

#[derive(Debug)]
pub struct BitcoindClientWithFallback {
    bitcoind_client: BitcoindClient,
    esplora_client: EsploraClient,
}

impl BitcoindClientWithFallback {
    pub fn new(
        username: String,
        password: String,
        bitcoind_url: &SafeUrl,
        esplora_url: &SafeUrl,
    ) -> Result<Self> {
        warn!(
            target: LOG_SERVER,
            %bitcoind_url,
            %esplora_url,
            "Initializing bitcoin bitcoind backend with esplora fallback"
        );
        let bitcoind_client = BitcoindClient::new(username, password, bitcoind_url)?;
        let esplora_client = EsploraClient::new(esplora_url)?;

        Ok(Self {
            bitcoind_client,
            esplora_client,
        })
    }
}

#[async_trait::async_trait]
impl IServerBitcoinRpc for BitcoindClientWithFallback {
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        self.bitcoind_client.get_bitcoin_rpc_config()
    }

    fn get_url(&self) -> SafeUrl {
        self.bitcoind_client.get_url()
    }

    async fn get_block_count(&self) -> Result<u64> {
        match self.bitcoind_client.get_block_count().await {
            Ok(count) => Ok(count),
            Err(e) => {
                warn!(
                    target: LOG_SERVER,
                    error = %e.fmt_compact_anyhow(),
                    "BitcoindClient failed for get_block_count, falling back to EsploraClient"
                );
                self.esplora_client.get_block_count().await
            }
        }
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        match self.bitcoind_client.get_block_hash(height).await {
            Ok(hash) => Ok(hash),
            Err(e) => {
                warn!(
                    target: LOG_SERVER,
                    error = %e.fmt_compact_anyhow(),
                    height = height,
                    "BitcoindClient failed for get_block_hash, falling back to EsploraClient"
                );
                self.esplora_client.get_block_hash(height).await
            }
        }
    }

    async fn get_block(&self, block_hash: &BlockHash) -> Result<bitcoin::Block> {
        match self.bitcoind_client.get_block(block_hash).await {
            Ok(block) => Ok(block),
            Err(e) => {
                warn!(
                    target: LOG_SERVER,
                    error = %e.fmt_compact_anyhow(),
                    block_hash = %block_hash,
                    "BitcoindClient failed for get_block, falling back to EsploraClient"
                );
                self.esplora_client.get_block(block_hash).await
            }
        }
    }

    async fn get_feerate(&self) -> Result<Option<Feerate>> {
        match self.bitcoind_client.get_feerate().await {
            Ok(feerate) => Ok(feerate),
            Err(e) => {
                warn!(
                    target: LOG_SERVER,
                    error = %e.fmt_compact_anyhow(),
                    "BitcoindClient failed for get_feerate, falling back to EsploraClient"
                );
                self.esplora_client.get_feerate().await
            }
        }
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        // Since this endpoint does not return an error, we can just always broadcast to
        // both places
        self.bitcoind_client
            .submit_transaction(transaction.clone())
            .await;
        self.esplora_client.submit_transaction(transaction).await;
    }

    async fn get_sync_progress(&self) -> Result<Option<f64>> {
        // We're always in sync, just like esplora
        self.esplora_client.get_sync_progress().await
    }

    async fn get_chain_id(&self) -> Result<ChainId> {
        match self.bitcoind_client.get_chain_id().await {
            Ok(chain_id) => Ok(chain_id),
            Err(e) => {
                warn!(
                    target: LOG_SERVER,
                    error = %e.fmt_compact_anyhow(),
                    "BitcoindClient failed for get_chain_id, falling back to EsploraClient"
                );
                self.esplora_client.get_chain_id().await
            }
        }
    }
}

/// A wrapper around `DynServerBitcoinRpc` that tracks metrics for each RPC
/// call.
///
/// This wrapper records the duration and success/error status of each
/// Bitcoin RPC call to Prometheus metrics, allowing monitoring of
/// Bitcoin node connectivity and performance on the server side.
pub struct ServerBitcoindTracked {
    inner: DynServerBitcoinRpc,
}

impl std::fmt::Debug for ServerBitcoindTracked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBitcoindTracked")
            .field("inner", &self.inner)
            .finish()
    }
}

impl ServerBitcoindTracked {
    /// Wraps a `DynServerBitcoinRpc` with metrics tracking.
    pub fn new(inner: DynServerBitcoinRpc) -> Self {
        Self { inner }
    }

    fn record_call<T>(&self, method: &str, result: &Result<T>) {
        let result_label = if result.is_ok() { "success" } else { "error" };
        SERVER_BITCOIND_RPC_REQUESTS_TOTAL
            .with_label_values(&[method, result_label])
            .inc();
    }
}

#[async_trait::async_trait]
impl IServerBitcoinRpc for ServerBitcoindTracked {
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        self.inner.get_bitcoin_rpc_config()
    }

    fn get_url(&self) -> SafeUrl {
        self.inner.get_url()
    }

    async fn get_block_count(&self) -> Result<u64> {
        let timer = SERVER_BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["get_block_count"])
            .start_timer_ext();
        let result = self.inner.get_block_count().await;
        timer.observe_duration();
        self.record_call("get_block_count", &result);
        result
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        let timer = SERVER_BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["get_block_hash"])
            .start_timer_ext();
        let result = self.inner.get_block_hash(height).await;
        timer.observe_duration();
        self.record_call("get_block_hash", &result);
        result
    }

    async fn get_block(&self, block_hash: &BlockHash) -> Result<bitcoin::Block> {
        let timer = SERVER_BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["get_block"])
            .start_timer_ext();
        let result = self.inner.get_block(block_hash).await;
        timer.observe_duration();
        self.record_call("get_block", &result);
        result
    }

    async fn get_feerate(&self) -> Result<Option<Feerate>> {
        let timer = SERVER_BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["get_feerate"])
            .start_timer_ext();
        let result = self.inner.get_feerate().await;
        timer.observe_duration();
        self.record_call("get_feerate", &result);
        result
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        let timer = SERVER_BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["submit_transaction"])
            .start_timer_ext();
        self.inner.submit_transaction(transaction).await;
        timer.observe_duration();
        // submit_transaction doesn't return a Result, so we always record success
        SERVER_BITCOIND_RPC_REQUESTS_TOTAL
            .with_label_values(&["submit_transaction", "success"])
            .inc();
    }

    async fn get_sync_progress(&self) -> Result<Option<f64>> {
        let timer = SERVER_BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["get_sync_progress"])
            .start_timer_ext();
        let result = self.inner.get_sync_progress().await;
        timer.observe_duration();
        self.record_call("get_sync_progress", &result);
        result
    }

    async fn get_chain_id(&self) -> Result<ChainId> {
        let timer = SERVER_BITCOIND_RPC_DURATION_SECONDS
            .with_label_values(&["get_chain_id"])
            .start_timer_ext();
        let result = self.inner.get_chain_id().await;
        timer.observe_duration();
        self.record_call("get_chain_id", &result);
        result
    }
}
