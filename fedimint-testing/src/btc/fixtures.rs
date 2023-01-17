use std::iter::repeat;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::Hash;
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{
    Address, Block, BlockHash, BlockHeader, Network, PackedLockTime, Transaction, TxOut,
};
use fedimint_api::{Amount, Feerate};
use fedimint_bitcoind::{IBitcoindRpc, Result as BitcoinRpcResult};
use fedimint_wallet::txoproof::TxOutProof;
use rand::rngs::OsRng;

use super::BitcoinTest;

#[derive(Clone, Debug)]
pub struct FakeBitcoinTest {
    blocks: Arc<Mutex<Vec<Block>>>,
    pending: Arc<Mutex<Vec<Transaction>>>,
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

impl BitcoinTest for FakeBitcoinTest {
    fn mine_blocks(&self, block_num: u64) {
        let mut blocks = self.blocks.lock().unwrap();
        let mut pending = self.pending.lock().unwrap();

        for _ in 1..=block_num {
            FakeBitcoinTest::mine_block(&mut blocks, &mut pending);
        }
    }

    fn send_and_mine_block(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> (TxOutProof, Transaction) {
        let mut blocks = self.blocks.lock().unwrap();
        let mut pending = self.pending.lock().unwrap();

        let transaction = FakeBitcoinTest::new_transaction(vec![TxOut {
            value: amount.to_sat(),
            script_pubkey: address.payload.script_pubkey(),
        }]);

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

    fn get_new_address(&self) -> Address {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let (_, public_key) = ctx.generate_keypair(&mut OsRng);

        Address::p2wpkh(&bitcoin::PublicKey::new(public_key), Network::Regtest).unwrap()
    }

    fn mine_block_and_get_received(&self, address: &Address) -> Amount {
        self.mine_blocks(1);
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

    async fn submit_transaction(&self, transaction: Transaction) -> BitcoinRpcResult<()> {
        let mut pending = self.pending.lock().unwrap();
        if !pending.contains(&transaction) {
            pending.push(transaction);
        }
        Ok(())
    }
}
