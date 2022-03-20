use crate::Feerate;
use async_trait::async_trait;
use bitcoin::{Block, BlockHash, Network, Transaction};
use bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use bitcoincore_rpc::RpcApi;
use tracing::warn;

/// Trait that allows interacting with the Bitcoin blockchain
///
/// Functions may panic if if the bitcoind node is not reachable.
#[async_trait]
pub trait BitcoindRpc: Send + Sync {
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

#[async_trait]
impl BitcoindRpc for bitcoincore_rpc::Client {
    async fn get_network(&self) -> Network {
        let network = tokio::task::block_in_place(|| self.get_blockchain_info())
            .expect("Bitcoind returned an error");
        match network.chain.as_str() {
            "main" => Network::Bitcoin,
            "test" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => panic!("Unknown Network"),
        }
    }

    async fn get_block_height(&self) -> u64 {
        tokio::task::block_in_place(|| self.get_block_count()).expect("Bitcoind returned an error")
    }

    async fn get_block_hash(&self, height: u64) -> BlockHash {
        tokio::task::block_in_place(|| bitcoincore_rpc::RpcApi::get_block_hash(self, height))
            .expect("Bitcoind returned an error")
    }

    async fn get_block(&self, hash: &BlockHash) -> Block {
        tokio::task::block_in_place(|| bitcoincore_rpc::RpcApi::get_block(self, hash))
            .expect("Bitcoind returned an error")
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> Option<Feerate> {
        tokio::task::block_in_place(|| {
            self.estimate_smart_fee(confirmation_target, Some(EstimateMode::Conservative))
        })
        .expect("Bitcoind returned an error") // TODO: implement retry logic in case bitcoind is temporarily unreachable
        .fee_rate
        .map(|per_kb| Feerate {
            sats_per_kvb: per_kb.as_sat(),
        })
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        if let Err(e) = tokio::task::block_in_place(|| self.send_raw_transaction(&transaction)) {
            warn!("Submitting transaction failed: {:?}", e);
        }
    }
}

#[allow(dead_code)]
pub mod test {
    use crate::bitcoind::BitcoindRpc;
    use crate::Feerate;
    use async_trait::async_trait;
    use bitcoin::hashes::Hash;
    use bitcoin::{Block, BlockHash, BlockHeader, Network, Transaction};
    use std::collections::{HashMap, VecDeque};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Debug, Default)]
    pub struct FakeBitcoindRpcState {
        fee_rate: Option<Feerate>,
        block_height: u64,
        transactions: VecDeque<Transaction>,
        tx_in_blocks: HashMap<BlockHash, Vec<Transaction>>,
    }

    #[derive(Clone, Default)]
    pub struct FakeBitcoindRpc {
        state: Arc<Mutex<FakeBitcoindRpcState>>,
    }

    pub struct FakeBitcoindRpcController {
        pub state: Arc<Mutex<FakeBitcoindRpcState>>,
    }

    #[async_trait]
    impl BitcoindRpc for FakeBitcoindRpc {
        async fn get_network(&self) -> Network {
            bitcoin::Network::Regtest
        }

        async fn get_block_height(&self) -> u64 {
            self.state.lock().await.block_height
        }

        async fn get_block_hash(&self, height: u64) -> BlockHash {
            height_hash(height)
        }

        async fn get_block(&self, hash: &BlockHash) -> Block {
            let txdata = self
                .state
                .lock()
                .await
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
            self.state.lock().await.fee_rate
        }

        async fn submit_transaction(&self, transaction: Transaction) {
            self.state.lock().await.transactions.push_back(transaction);
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
            self.state.lock().await.fee_rate = fee_rate;
        }

        pub async fn set_block_height(&self, block_height: u64) {
            self.state.lock().await.block_height = block_height
        }

        pub async fn is_btc_sent_to(
            &self,
            amount: bitcoin::Amount,
            recipient: bitcoin::Address,
        ) -> bool {
            self.state
                .lock()
                .await
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
            let mut state = self.state.lock().await;
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
