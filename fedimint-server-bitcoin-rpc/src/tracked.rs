use anyhow::Result;
use bitcoin::{Block, BlockHash, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::time::now;
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl};
use fedimint_core::{ChainId, Feerate};
use fedimint_logging::LOG_BITCOIND;
use fedimint_metrics::HistogramExt as _;
use fedimint_server_core::bitcoin_rpc::{DynServerBitcoinRpc, IServerBitcoinRpc};
use tracing::trace;

use crate::metrics::{SERVER_BITCOIN_RPC_DURATION_SECONDS, SERVER_BITCOIN_RPC_REQUESTS_TOTAL};

pub struct ServerBitcoinRpcTracked {
    inner: DynServerBitcoinRpc,
    name: &'static str,
}

impl std::fmt::Debug for ServerBitcoinRpcTracked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBitcoinRpcTracked")
            .field("name", &self.name)
            .field("inner", &self.inner)
            .finish()
    }
}

impl ServerBitcoinRpcTracked {
    pub fn new(inner: DynServerBitcoinRpc, name: &'static str) -> Self {
        Self { inner, name }
    }

    fn record_call<T>(&self, method: &str, result: &Result<T>) {
        let result_label = if result.is_ok() { "success" } else { "error" };
        SERVER_BITCOIN_RPC_REQUESTS_TOTAL
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
        let timer = SERVER_BITCOIN_RPC_DURATION_SECONDS
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
        match &result {
            Ok(_) => {
                trace!(
                    target: LOG_BITCOIND,
                    method = $method,
                    name = $self.name,
                    duration_ms,
                    "completed bitcoind rpc"
                );
            }
            Err(err) => {
                trace!(
                    target: LOG_BITCOIND,
                    method = $method,
                    name = $self.name,
                    duration_ms,
                    error = %err.fmt_compact_anyhow(),
                    "completed bitcoind rpc with error"
                );
            }
        }
        result
    }};
}

#[async_trait::async_trait]
impl IServerBitcoinRpc for ServerBitcoinRpcTracked {
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        self.inner.get_bitcoin_rpc_config()
    }

    fn get_url(&self) -> SafeUrl {
        self.inner.get_url()
    }

    async fn get_block_count(&self) -> Result<u64> {
        tracked_call!(self, "get_block_count", self.inner.get_block_count().await)
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        tracked_call!(
            self,
            "get_block_hash",
            self.inner.get_block_hash(height).await
        )
    }

    async fn get_block(&self, block_hash: &BlockHash) -> Result<Block> {
        tracked_call!(self, "get_block", self.inner.get_block(block_hash).await)
    }

    async fn get_feerate(&self) -> Result<Option<Feerate>> {
        tracked_call!(self, "get_feerate", self.inner.get_feerate().await)
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        trace!(
            target: LOG_BITCOIND,
            method = "submit_transaction",
            name = self.name,
            "starting bitcoind rpc"
        );
        let start = now();
        let timer = SERVER_BITCOIN_RPC_DURATION_SECONDS
            .with_label_values(&["submit_transaction", self.name])
            .start_timer_ext();
        self.inner.submit_transaction(transaction).await;
        timer.observe_duration();
        let duration_ms = now()
            .duration_since(start)
            .unwrap_or_default()
            .as_secs_f64()
            * 1000.0;
        trace!(
            target: LOG_BITCOIND,
            method = "submit_transaction",
            name = self.name,
            duration_ms,
            "completed bitcoind rpc"
        );
    }

    async fn get_sync_progress(&self) -> Result<Option<f64>> {
        tracked_call!(
            self,
            "get_sync_progress",
            self.inner.get_sync_progress().await
        )
    }

    async fn get_chain_id(&self) -> Result<ChainId> {
        tracked_call!(self, "get_chain_id", self.inner.get_chain_id().await)
    }
}
