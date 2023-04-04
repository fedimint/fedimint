use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{Block, BlockHash, BlockHeader, Network, Transaction};
use fedimint_bitcoind::{IBitcoindRpc, Result};
use fedimint_core::Feerate;

#[derive(Debug, Default)]
pub struct FakeBitcoindRpcState {
    fee_rate: Option<Feerate>,
    block_height: u64,
    transactions: VecDeque<Transaction>,
    tx_in_blocks: HashMap<BlockHash, Vec<Transaction>>,
}

#[derive(Debug, Default, Clone)]
pub struct FakeBitcoindRpc {
    state: Arc<Mutex<FakeBitcoindRpcState>>,
}

pub struct FakeBitcoindRpcController {
    pub state: Arc<Mutex<FakeBitcoindRpcState>>,
}

#[async_trait]
impl IBitcoindRpc for FakeBitcoindRpc {
    async fn get_network(&self) -> Result<Network> {
        Ok(bitcoin::Network::Regtest)
    }

    async fn get_block_height(&self) -> Result<u64> {
        Ok(self.state.lock().unwrap().block_height)
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        Ok(height_hash(height))
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        let txdata = self
            .state
            .lock()
            .unwrap()
            .tx_in_blocks
            .get(hash)
            .cloned()
            .unwrap_or_default();
        Ok(Block {
            header: BlockHeader {
                version: 0,
                prev_blockhash: sha256d::Hash::hash(b"").into(),
                merkle_root: sha256d::Hash::hash(b"").into(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txdata,
        })
    }

    async fn get_fee_rate(&self, _confirmation_target: u16) -> Result<Option<Feerate>> {
        Ok(self.state.lock().unwrap().fee_rate)
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
                output.value == amount.to_sat() && output.script_pubkey == recipient.script_pubkey()
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
