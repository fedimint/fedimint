use std::sync::Arc;

use crate::Feerate;
use async_trait::async_trait;
use bitcoin::{BlockHash, Transaction};
use fedimint_api::dyn_newtype_define;

/// Trait that allows interacting with the Bitcoin blockchain
///
/// Functions may panic if if the bitcoind node is not reachable.
#[async_trait]
pub trait IBitcoindRpc: Send + Sync {
    /// Returns the Bitcoin network the node is connected to
    async fn get_network(&self) -> bitcoin::Network;

    /// Returns the current block height
    async fn get_block_height(&self) -> u64;

    /// Returns the block hash at a given height
    ///
    /// # Panics
    /// If the node does not know a block for that height. Make sure to only query blocks of a
    /// height less or equal to the one returned by `Self::get_block_height`.
    ///
    /// While there is a corner case that the blockchain shrinks between these two calls (through on
    /// average heavier blocks on a fork) this is prevented by only querying hashes for blocks
    /// tailing the chain tip by a certain number of blocks.
    async fn get_block_hash(&self, height: u64) -> BlockHash;

    /// Returns the block with the given hash
    ///
    /// # Panics
    /// If the block doesn't exist.
    async fn get_block(&self, hash: &BlockHash) -> bitcoin::Block;

    /// Estimates the fee rate for a given confirmation target. Make sure that all federation
    /// members use the same algorithm to avoid widely diverging results. If the node is not ready
    /// yet to return a fee rate estimation this function returns `None`.
    async fn get_fee_rate(&self, confirmation_target: u16) -> Option<Feerate>;

    /// Submits a transaction to the Bitcoin network
    ///
    /// # Panics
    /// If the transaction is deemed invalid by the node it was submitted to
    async fn submit_transaction(&self, transaction: Transaction);
}

dyn_newtype_define! {
    #[derive(Clone)]
    BitcoindRpc(Arc<IBitcoindRpc>)
}

#[allow(dead_code)]
pub mod test {
    use super::IBitcoindRpc;
    use crate::Feerate;
    use async_trait::async_trait;
    use bitcoin::hashes::Hash;
    use bitcoin::{Block, BlockHash, BlockHeader, Network, Transaction};
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    pub struct FakeBitcoindRpcState {
        fee_rate: Option<Feerate>,
        block_height: u64,
        transactions: VecDeque<Transaction>,
        tx_in_blocks: HashMap<BlockHash, Vec<Transaction>>,
    }

    #[derive(Default, Clone)]
    pub struct FakeBitcoindRpc {
        state: Arc<Mutex<FakeBitcoindRpcState>>,
    }

    pub struct FakeBitcoindRpcController {
        pub state: Arc<Mutex<FakeBitcoindRpcState>>,
    }

    #[async_trait]
    impl IBitcoindRpc for FakeBitcoindRpc {
        async fn get_network(&self) -> Network {
            bitcoin::Network::Regtest
        }

        async fn get_block_height(&self) -> u64 {
            self.state.lock().unwrap().block_height
        }

        async fn get_block_hash(&self, height: u64) -> BlockHash {
            height_hash(height)
        }

        async fn get_block(&self, hash: &BlockHash) -> Block {
            let txdata = self
                .state
                .lock()
                .unwrap()
                .tx_in_blocks
                .get(hash)
                .cloned()
                .unwrap_or_default();
            Block {
                header: BlockHeader {
                    version: 0,
                    prev_blockhash: Default::default(),
                    merkle_root: Default::default(),
                    time: 0,
                    bits: 0,
                    nonce: 0,
                },
                txdata,
            }
        }

        async fn get_fee_rate(&self, _confirmation_target: u16) -> Option<Feerate> {
            self.state.lock().unwrap().fee_rate
        }

        async fn submit_transaction(&self, transaction: Transaction) {
            self.state
                .lock()
                .unwrap()
                .transactions
                .push_back(transaction);
        }
    }

    impl FakeBitcoindRpc {
        pub fn new() -> FakeBitcoindRpc {
            FakeBitcoindRpc::default()
        }

        pub fn controller(&self) -> FakeBitcoindRpcController {
            FakeBitcoindRpcController {
                state: self.state.clone(),
            }
        }
    }

    impl FakeBitcoindRpcController {
        pub async fn set_fee_rate(&self, fee_rate: Option<Feerate>) {
            self.state.lock().unwrap().fee_rate = fee_rate;
        }

        pub async fn set_block_height(&self, block_height: u64) {
            self.state.lock().unwrap().block_height = block_height
        }

        pub async fn is_btc_sent_to(
            &self,
            amount: bitcoin::Amount,
            recipient: bitcoin::Address,
        ) -> bool {
            self.state
                .lock()
                .unwrap()
                .transactions
                .iter()
                .flat_map(|tx| tx.output.iter())
                .any(|output| {
                    output.value == amount.as_sat()
                        && output.script_pubkey == recipient.script_pubkey()
                })
        }

        pub async fn add_pending_tx_to_block(&self, block: u64) {
            let block_hash = height_hash(block);
            let mut state = self.state.lock().unwrap();
            #[allow(clippy::needless_collect)]
            let txns = state.transactions.drain(..).collect::<Vec<_>>();
            state
                .tx_in_blocks
                .entry(block_hash)
                .or_default()
                .extend(txns.into_iter());
        }
    }

    fn height_hash(height: u64) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&height.to_le_bytes()[..]);
        BlockHash::from_inner(bytes)
    }
}
