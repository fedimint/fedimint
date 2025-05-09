use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use fedimint_core::Feerate;
use fedimint_core::bitcoin::{Block, BlockHash, Network, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_SERVER;
use tokio::sync::watch;
use tracing::debug;

use crate::dashboard_ui::ServerBitcoinRpcStatus;

#[derive(Debug, Clone)]
pub struct ServerBitcoinRpcMonitor {
    rpc: DynServerBitcoinRpc,
    status_receiver: watch::Receiver<Option<ServerBitcoinRpcStatus>>,
}

impl ServerBitcoinRpcMonitor {
    pub fn new(
        rpc: DynServerBitcoinRpc,
        update_interval: Duration,
        task_group: &TaskGroup,
    ) -> Self {
        let (status_sender, status_receiver) = watch::channel(None);

        let rpc_clone = rpc.clone();
        debug!(
            target: LOG_SERVER,
            interval_ms  = %update_interval.as_millis(),
            "Starting bitcoin rpc monitor"
        );

        task_group.spawn_cancellable("bitcoin-status-update", async move {
            let mut interval = tokio::time::interval(update_interval);
            loop {
                interval.tick().await;
                match Self::fetch_status(&rpc_clone).await {
                    Ok(new_status) => {
                        status_sender.send_replace(Some(new_status));
                    }
                    Err(..) => {
                        status_sender.send_replace(None);
                    }
                }
            }
        });

        Self {
            rpc,
            status_receiver,
        }
    }

    async fn fetch_status(rpc: &DynServerBitcoinRpc) -> Result<ServerBitcoinRpcStatus> {
        let network = rpc.get_network().await?;
        let block_count = rpc.get_block_count().await?;
        let sync_percentage = rpc.get_sync_percentage().await?;

        let fee_rate = if network == Network::Regtest {
            Feerate { sats_per_kvb: 1000 }
        } else {
            rpc.get_feerate().await?.context("Feerate not available")?
        };

        Ok(ServerBitcoinRpcStatus {
            network,
            block_count,
            fee_rate,
            sync_percentage,
        })
    }

    pub fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        self.rpc.get_bitcoin_rpc_config()
    }

    pub fn url(&self) -> SafeUrl {
        self.rpc.get_url()
    }

    pub fn status(&self) -> Option<ServerBitcoinRpcStatus> {
        self.status_receiver.borrow().clone()
    }

    pub async fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        ensure!(
            self.status_receiver.borrow().is_some(),
            "Not connected to bitcoin backend"
        );

        self.rpc.get_block(hash).await
    }

    pub async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        ensure!(
            self.status_receiver.borrow().is_some(),
            "Not connected to bitcoin backend"
        );

        self.rpc.get_block_hash(height).await
    }

    pub async fn submit_transaction(&self, tx: Transaction) {
        if self.status_receiver.borrow().is_some() {
            self.rpc.submit_transaction(tx).await;
        }
    }
}

pub type DynServerBitcoinRpc = Arc<dyn IServerBitcoinRpc>;

#[async_trait::async_trait]
pub trait IServerBitcoinRpc: Debug + Send + Sync + 'static {
    /// Returns the Bitcoin RPC config
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig;

    /// Returns the Bitcoin RPC url
    fn get_url(&self) -> SafeUrl;

    /// Returns the Bitcoin network the node is connected to
    async fn get_network(&self) -> Result<Network>;

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
    async fn get_feerate(&self) -> Result<Option<Feerate>>;

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

    /// Returns the node's estimated chain sync percentage as a float between
    /// 0.0 and 1.0, or `None` if the node doesn't support this feature.
    async fn get_sync_percentage(&self) -> Result<Option<f64>>;

    fn into_dyn(self) -> DynServerBitcoinRpc
    where
        Self: Sized,
    {
        Arc::new(self)
    }
}
