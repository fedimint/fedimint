use std::collections::{BTreeMap, HashMap, VecDeque};
use std::iter::repeat;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{
    Address, Block, BlockHash, BlockHeader, Network, OutPoint, PackedLockTime, Transaction, TxOut,
};
use fedimint_bitcoind::{IBitcoindRpc, Result as BitcoinRpcResult};
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::{Amount, Feerate};
use rand::rngs::OsRng;

use super::BitcoinTest;

#[derive(Clone, Debug)]
pub struct FakeBitcoinTest {
    /// Simulates mined bitcoin blocks
    blocks: Arc<Mutex<Vec<Block>>>,
    /// Simulates pending transactions in the mempool
    pending: Arc<Mutex<Vec<Transaction>>>,
    /// Tracks how much bitcoin was sent to an address (doesn't track sending
    /// out of it)
    addresses: Arc<Mutex<BTreeMap<Txid, Amount>>>,
}

impl Default for FakeBitcoinTest {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeBitcoinTest {
    pub fn new() -> Self {
        FakeBitcoinTest {
            blocks: Arc::new(Mutex::new(vec![])),
            pending: Arc::new(Mutex::new(vec![])),
            addresses: Arc::new(Mutex::new(Default::default())),
        }
    }

    fn pending_merkle_tree(pending: &[Transaction]) -> PartialMerkleTree {
        let txs = pending.iter().map(|tx| tx.txid()).collect::<Vec<Txid>>();
        let matches = repeat(true).take(txs.len()).collect::<Vec<bool>>();
        PartialMerkleTree::from_txids(txs.as_slice(), matches.as_slice())
    }

    fn new_transaction(out: Vec<TxOut>) -> Transaction {
        Transaction {
            version: 0,
            lock_time: PackedLockTime::ZERO,
            input: vec![],
            output: out,
        }
    }

    fn mine_block(blocks: &mut Vec<Block>, pending: &mut Vec<Transaction>) {
        let root = BlockHash::hash(&[0]);
        // all blocks need at least one transaction
        if pending.is_empty() {
            pending.push(Self::new_transaction(vec![]));
        }
        let merkle_root = Self::pending_merkle_tree(pending)
            .extract_matches(&mut vec![], &mut vec![])
            .unwrap();
        let block = Block {
            header: BlockHeader {
                version: 0,
                prev_blockhash: blocks.last().map(|b| b.header.block_hash()).unwrap_or(root),
                merkle_root,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txdata: pending.clone(),
        };
        pending.clear();
        blocks.push(block);
    }
}

#[async_trait]
impl BitcoinTest for FakeBitcoinTest {
    async fn lock_exclusive(&self) -> Box<dyn BitcoinTest + Send> {
        // With  FakeBitcoinTest, every test spawns their own instance,
        // so not need to lock anything
        Box::new(self.clone())
    }

    async fn mine_blocks(&self, block_num: u64) {
        let mut blocks = self.blocks.lock().unwrap();
        let mut pending = self.pending.lock().unwrap();

        for _ in 1..=block_num {
            FakeBitcoinTest::mine_block(&mut blocks, &mut pending);
        }
    }

    async fn prepare_funding_wallet(&self) {
        // In fake wallet this might not be technically necessary,
        // but it makes it behave more like the `RealBitcoinTest`.
        let block_count = self.blocks.lock().unwrap().len() as u64;
        if block_count < 100 {
            self.mine_blocks(100 - block_count).await;
        }
    }

    async fn send_and_mine_block(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> (TxOutProof, Transaction) {
        let mut blocks = self.blocks.lock().unwrap();
        let mut pending = self.pending.lock().unwrap();
        let mut addresses = self.addresses.lock().unwrap();

        let transaction = FakeBitcoinTest::new_transaction(vec![TxOut {
            value: amount.to_sat(),
            script_pubkey: address.payload.script_pubkey(),
        }]);
        addresses.insert(transaction.txid(), amount.into());

        pending.push(transaction.clone());
        let merkle_proof = FakeBitcoinTest::pending_merkle_tree(&pending);

        FakeBitcoinTest::mine_block(&mut blocks, &mut pending);
        let block_header = blocks.last().unwrap().header;

        (
            TxOutProof {
                block_header,
                merkle_proof,
            },
            transaction,
        )
    }

    async fn get_new_address(&self) -> Address {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let (_, public_key) = ctx.generate_keypair(&mut OsRng);

        Address::p2wpkh(&bitcoin::PublicKey::new(public_key), Network::Regtest).unwrap()
    }

    async fn mine_block_and_get_received(&self, address: &Address) -> Amount {
        self.mine_blocks(1).await;
        let sats = self
            .blocks
            .lock()
            .unwrap()
            .clone()
            .into_iter()
            .flat_map(|block| block.txdata.into_iter().flat_map(|tx| tx.output))
            .find(|out| out.script_pubkey == address.payload.script_pubkey())
            .map(|tx| tx.value)
            .unwrap_or(0);
        Amount::from_sats(sats)
    }

    async fn get_mempool_tx_fee(&self, txid: &Txid) -> Amount {
        let pending = self.pending.lock().unwrap();
        let addresses = self.addresses.lock().unwrap();

        let mut fee = Amount::ZERO;
        let tx = pending
            .iter()
            .find(|tx| tx.txid() == *txid)
            .expect("tx was broadcast");

        for input in tx.input.iter() {
            fee += *addresses
                .get(&input.previous_output.txid)
                .expect("tx has sats");
        }

        for output in tx.output.iter() {
            fee -= Amount::from_sats(output.value);
        }

        fee
    }
}

#[async_trait]
impl IBitcoindRpc for FakeBitcoinTest {
    async fn get_network(&self) -> BitcoinRpcResult<Network> {
        Ok(Network::Regtest)
    }

    async fn get_block_height(&self) -> BitcoinRpcResult<u64> {
        Ok(self.blocks.lock().unwrap().len() as u64)
    }

    async fn get_block_hash(&self, height: u64) -> BitcoinRpcResult<BlockHash> {
        Ok(self.blocks.lock().unwrap()[(height - 1) as usize]
            .header
            .block_hash())
    }

    async fn get_block(&self, hash: &BlockHash) -> BitcoinRpcResult<Block> {
        Ok(self
            .blocks
            .lock()
            .unwrap()
            .iter()
            .find(|block| *hash == block.header.block_hash())
            .unwrap()
            .clone())
    }

    async fn get_fee_rate(&self, _confirmation_target: u16) -> BitcoinRpcResult<Option<Feerate>> {
        Ok(None)
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        let mut pending = self.pending.lock().unwrap();
        pending.push(transaction);

        let mut filtered = BTreeMap::<Vec<OutPoint>, Transaction>::new();

        // Simulate the mempool keeping txs with higher fees (less output)
        for tx in pending.iter() {
            match filtered.get(&inputs(tx)) {
                Some(found) if output_sum(tx) > output_sum(found) => {}
                _ => {
                    filtered.insert(inputs(tx), tx.clone());
                }
            }
        }

        *pending = filtered.into_values().collect();
    }
}

fn output_sum(tx: &Transaction) -> u64 {
    tx.output.iter().map(|output| output.value).sum()
}

fn inputs(tx: &Transaction) -> Vec<OutPoint> {
    tx.input.iter().map(|input| input.previous_output).collect()
}

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
    async fn get_network(&self) -> anyhow::Result<Network> {
        Ok(bitcoin::Network::Regtest)
    }

    async fn get_block_height(&self) -> anyhow::Result<u64> {
        Ok(self.state.lock().unwrap().block_height)
    }

    async fn get_block_hash(&self, height: u64) -> anyhow::Result<BlockHash> {
        Ok(height_hash(height))
    }

    async fn get_block(&self, hash: &BlockHash) -> anyhow::Result<Block> {
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

    async fn get_fee_rate(&self, _confirmation_target: u16) -> anyhow::Result<Option<Feerate>> {
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
    // Exceptionally use little endian to match bitcoin consensus encoding
    bytes[..8].copy_from_slice(&height.to_le_bytes()[..]);
    BlockHash::from_inner(bytes)
}
