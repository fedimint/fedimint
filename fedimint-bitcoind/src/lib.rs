use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
pub use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{Block, BlockHash, Network, Transaction};
use fedimint_api::{
    bitcoin_rpc::BitcoinRpcBackendType, dyn_newtype_define, task::TaskHandle, Feerate,
};
use tracing::info;

#[cfg(feature = "bitcoincore-rpc")]
pub mod bitcoincore_rpc;

/// Trait that allows interacting with the Bitcoin blockchain
///
/// Functions may panic if if the bitcoind node is not reachable.
#[async_trait]
pub trait IBitcoindRpc: Debug + Send + Sync {
    /// `true` if it's real-bitcoin (not electrum) backend and thus supports
    /// `get_block` call
    ///
    /// This is a bit of a workaround to support electrum.
    fn backend_type(&self) -> BitcoinRpcBackendType {
        BitcoinRpcBackendType::Bitcoind
    }

    /// Returns the Bitcoin network the node is connected to
    async fn get_network(&self) -> Result<bitcoin::Network>;

    /// Returns the current block height
    async fn get_block_height(&self) -> Result<u64>;

    /// Returns the block hash at a given height
    ///
    /// # Panics
    /// If the node does not know a block for that height. Make sure to only
    /// query blocks of a height less or equal to the one returned by
    /// `Self::get_block_height`.
    ///
    /// While there is a corner case that the blockchain shrinks between these
    /// two calls (through on average heavier blocks on a fork) this is
    /// prevented by only querying hashes for blocks tailing the chain tip
    /// by a certain number of blocks.
    async fn get_block_hash(&self, height: u64) -> Result<BlockHash>;

    /// Returns the block with the given hash
    ///
    /// # Panics
    /// If the block doesn't exist.
    async fn get_block(&self, hash: &BlockHash) -> Result<bitcoin::Block>;

    /// Estimates the fee rate for a given confirmation target. Make sure that
    /// all federation members use the same algorithm to avoid widely
    /// diverging results. If the node is not ready yet to return a fee rate
    /// estimation this function returns `None`.
    async fn get_fee_rate(&self, confirmation_target: u16) -> Result<Option<Feerate>>;

    /// Submits a transaction to the Bitcoin network
    async fn submit_transaction(&self, transaction: Transaction) -> Result<()>;

    /// Check if a transaction was included in a given (only electrum)
    async fn was_transaction_confirmed_in(
        &self,
        _transaction: &Transaction,
        _height: u64,
    ) -> Result<bool> {
        bail!("is_transaction_confirmed_in call not supported in standard (non-electrum) backends")
    }
}

dyn_newtype_define! {
    #[derive(Clone)]
    pub DynBitcoindRpc(Arc<IBitcoindRpc>)
}

/// Wrapper around [`IBitcoindRpc`] that will retry failed calls
#[derive(Debug)]
pub struct RetryClient<C> {
    inner: C,
    sleep: Duration,
    task_handle: TaskHandle,
}

impl<C> RetryClient<C> {
    pub fn new(inner: C, task_handle: TaskHandle) -> Self {
        Self {
            inner,
            sleep: Duration::from_millis(10),
            task_handle,
        }
    }

    async fn retry_call<T, F, R>(&self, call_fn: F) -> Result<T>
    where
        F: Fn() -> R,
        R: Future<Output = Result<T>>,
    {
        let ret = loop {
            match call_fn().await {
                Ok(ret) => {
                    break ret;
                }
                Err(e) => {
                    if self.task_handle.is_shutting_down() {
                        return Err(e);
                    }

                    info!("Bitcoind error {:?}, retrying", e);
                    std::thread::sleep(self.sleep);
                }
            }
        };
        Ok(ret)
    }
}

#[async_trait]
impl<C> IBitcoindRpc for RetryClient<C>
where
    C: IBitcoindRpc,
{
    fn backend_type(&self) -> BitcoinRpcBackendType {
        self.inner.backend_type()
    }

    async fn get_network(&self) -> Result<Network> {
        self.retry_call(|| async { self.inner.get_network().await })
            .await
    }

    async fn get_block_height(&self) -> Result<u64> {
        self.retry_call(|| async { self.inner.get_block_height().await })
            .await
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        self.retry_call(|| async { self.inner.get_block_hash(height).await })
            .await
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        self.retry_call(|| async { self.inner.get_block(hash).await })
            .await
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> Result<Option<Feerate>> {
        self.retry_call(|| async { self.inner.get_fee_rate(confirmation_target).await })
            .await
    }

    async fn submit_transaction(&self, transaction: Transaction) -> Result<()> {
        self.retry_call(|| async { self.inner.submit_transaction(transaction.clone()).await })
            .await
    }

    async fn was_transaction_confirmed_in(
        &self,
        transaction: &Transaction,
        height: u64,
    ) -> Result<bool> {
        self.retry_call(|| async {
            self.inner
                .was_transaction_confirmed_in(transaction, height)
                .await
        })
        .await
    }
}
