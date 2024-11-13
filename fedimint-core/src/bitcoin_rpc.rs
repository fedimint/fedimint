use std::fmt::Debug;
use std::sync::Arc;

use anyhow::Result;
use bitcoin::{BlockHash, ScriptBuf, Transaction, Txid};
use macro_rules_attribute::apply;

use crate::envs::BitcoinRpcConfig;
use crate::txoproof::TxOutProof;
use crate::{async_trait_maybe_send, dyn_newtype_define, Feerate};

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

    /// Returns the Bitcoin RPC config
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig;
}

dyn_newtype_define! {
    #[derive(Clone)]
    pub DynBitcoindRpc(Arc<IBitcoindRpc>)
}
