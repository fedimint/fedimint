use std::collections::BTreeMap;
use std::iter::repeat;
use std::sync::Arc;
use std::time::Duration;

use anyhow::format_err;
use async_trait::async_trait;
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header as BlockHeader, Version};
use bitcoin::constants::genesis_block;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::Hash;
use bitcoin::merkle_tree::PartialMerkleTree;
use bitcoin::{
    Address, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Transaction, TxOut,
};
use fedimint_bitcoind::{
    register_bitcoind, DynBitcoindRpc, IBitcoindRpc, IBitcoindRpcFactory,
    Result as BitcoinRpcResult,
};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::task::{sleep_in_test, TaskHandle};
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, Feerate};
use rand::rngs::OsRng;
use tracing::debug;

use super::BitcoinTest;

#[derive(Debug, Clone)]
pub struct FakeBitcoinFactory {
    pub bitcoin: FakeBitcoinTest,
    pub config: BitcoinRpcConfig,
}

impl FakeBitcoinFactory {
    /// Registers a fake bitcoin rpc factory for testing
    pub fn register_new() -> FakeBitcoinFactory {
        let kind = format!("test_btc-{}", rand::random::<u64>());
        let factory = FakeBitcoinFactory {
            bitcoin: FakeBitcoinTest::new(),
            config: BitcoinRpcConfig {
                kind: kind.clone(),
                url: "http://ignored".parse().unwrap(),
            },
        };
        register_bitcoind(kind, factory.clone().into());
        factory
    }
}

impl IBitcoindRpcFactory for FakeBitcoinFactory {
    fn create_connection(
        &self,
        _url: &SafeUrl,
        _handle: TaskHandle,
    ) -> anyhow::Result<DynBitcoindRpc> {
        Ok(self.bitcoin.clone().into())
    }
}

#[derive(Debug)]
struct FakeBitcoinTestInner {
    /// Simulates mined bitcoin blocks
    blocks: Vec<Block>,
    /// Simulates pending transactions in the mempool
    pending: Vec<Transaction>,
    /// Tracks how much bitcoin was sent to an address (doesn't track sending
    /// out of it)
    addresses: BTreeMap<Txid, Amount>,
    /// Simulates the merkle tree proofs
    proofs: BTreeMap<Txid, TxOutProof>,
    /// Simulates the script history
    scripts: BTreeMap<ScriptBuf, Vec<Transaction>>,
    /// Tracks the block height a transaction was included
    txid_to_block_height: BTreeMap<Txid, usize>,
}

#[derive(Clone, Debug)]
pub struct FakeBitcoinTest {
    inner: Arc<std::sync::RwLock<FakeBitcoinTestInner>>,
}

impl Default for FakeBitcoinTest {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeBitcoinTest {
    pub fn new() -> Self {
        let inner = FakeBitcoinTestInner {
            blocks: vec![genesis_block(Network::Regtest)],
            pending: vec![],
            addresses: BTreeMap::new(),
            proofs: BTreeMap::new(),
            scripts: BTreeMap::new(),
            txid_to_block_height: BTreeMap::new(),
        };
        FakeBitcoinTest {
            inner: std::sync::RwLock::new(inner).into(),
        }
    }

    fn pending_merkle_tree(pending: &[Transaction]) -> PartialMerkleTree {
        let txs = pending.iter().map(Transaction::txid).collect::<Vec<Txid>>();
        let matches = repeat(true).take(txs.len()).collect::<Vec<bool>>();
        PartialMerkleTree::from_txids(txs.as_slice(), matches.as_slice())
    }

    /// Create a fake bitcoin transaction with given outputs
    ///
    /// Nonce is used to avoid same txids for transactions with same outputs,
    /// which can accidenatally happen due to how simplicit our fakes are.
    fn new_transaction(out: Vec<TxOut>, nonce: u32) -> Transaction {
        Transaction {
            version: 0,
            lock_time: LockTime::from_height(nonce).unwrap(),
            input: vec![],
            output: out,
        }
    }

    fn mine_block(
        addresses: &mut BTreeMap<Txid, Amount>,
        blocks: &mut Vec<Block>,
        pending: &mut Vec<Transaction>,
        txid_to_block_height: &mut BTreeMap<Txid, usize>,
    ) -> bitcoin::BlockHash {
        debug!(
            "Mining block: {} transactions, {} blocks",
            pending.len(),
            blocks.len()
        );
        let root = BlockHash::hash(&[0]);
        // block height is 0-based, so blocks.len() before appending the current block
        // gives the correct height
        let block_height = blocks.len();
        for tx in pending.iter() {
            addresses.insert(tx.txid(), Amount::from_sats(output_sum(tx)));
            txid_to_block_height.insert(tx.txid(), block_height);
        }
        // all blocks need at least one transaction
        if pending.is_empty() {
            pending.push(Self::new_transaction(vec![], blocks.len() as u32));
        }
        let merkle_root = Self::pending_merkle_tree(pending)
            .extract_matches(&mut vec![], &mut vec![])
            .unwrap();
        let block = Block {
            header: BlockHeader {
                version: Version::from_consensus(0),
                prev_blockhash: blocks.last().map_or(root, |b| b.header.block_hash()),
                merkle_root,
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: pending.clone(),
        };
        pending.clear();
        blocks.push(block.clone());
        block.block_hash()
    }
}

#[async_trait]
impl BitcoinTest for FakeBitcoinTest {
    async fn lock_exclusive(&self) -> Box<dyn BitcoinTest + Send + Sync> {
        // With  FakeBitcoinTest, every test spawns their own instance,
        // so not need to lock anything
        Box::new(self.clone())
    }

    async fn mine_blocks(&self, block_num: u64) -> Vec<bitcoin::BlockHash> {
        let mut inner = self.inner.write().unwrap();

        let FakeBitcoinTestInner {
            ref mut blocks,
            ref mut pending,
            ref mut addresses,
            ref mut txid_to_block_height,
            ..
        } = *inner;

        (1..=block_num)
            .map(|_| FakeBitcoinTest::mine_block(addresses, blocks, pending, txid_to_block_height))
            .collect()
    }

    async fn prepare_funding_wallet(&self) {
        // In fake wallet this might not be technically necessary,
        // but it makes it behave more like the `RealBitcoinTest`.
        let block_count = self.inner.write().unwrap().blocks.len() as u64;
        if block_count < 100 {
            self.mine_blocks(100 - block_count).await;
        }
    }

    async fn send_and_mine_block(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> (TxOutProof, Transaction) {
        let mut inner = self.inner.write().unwrap();

        let transaction = FakeBitcoinTest::new_transaction(
            vec![TxOut {
                value: amount.to_sat(),
                script_pubkey: address.payload.script_pubkey(),
            }],
            inner.blocks.len() as u32,
        );
        inner.addresses.insert(transaction.txid(), amount.into());

        inner.pending.push(transaction.clone());
        let merkle_proof = FakeBitcoinTest::pending_merkle_tree(&inner.pending);

        let FakeBitcoinTestInner {
            ref mut blocks,
            ref mut pending,
            ref mut addresses,
            ref mut txid_to_block_height,
            ..
        } = *inner;
        FakeBitcoinTest::mine_block(addresses, blocks, pending, txid_to_block_height);
        let block_header = inner.blocks.last().unwrap().header;
        let proof = TxOutProof {
            block_header,
            merkle_proof,
        };
        inner.proofs.insert(transaction.txid(), proof.clone());
        inner
            .scripts
            .insert(address.payload.script_pubkey(), vec![transaction.clone()]);

        (proof, transaction)
    }

    async fn get_new_address(&self) -> Address {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let (_, public_key) = ctx.generate_keypair(&mut OsRng);

        Address::p2wpkh(&bitcoin::PublicKey::new(public_key), Network::Regtest).unwrap()
    }

    async fn mine_block_and_get_received(&self, address: &Address) -> Amount {
        self.mine_blocks(1).await;
        let sats = self
            .inner
            .read()
            .unwrap()
            .blocks
            .iter()
            .flat_map(|block| block.txdata.iter().flat_map(|tx| tx.output.clone()))
            .find(|out| out.script_pubkey == address.payload.script_pubkey())
            .map_or(0, |tx| tx.value);
        Amount::from_sats(sats)
    }

    async fn get_mempool_tx_fee(&self, txid: &Txid) -> Amount {
        loop {
            let (pending, addresses) = {
                let inner = self.inner.read().unwrap();
                (inner.pending.clone(), inner.addresses.clone())
            };

            let mut fee = Amount::ZERO;
            let maybe_tx = pending.iter().find(|tx| tx.txid() == *txid);

            let tx = match maybe_tx {
                None => {
                    sleep_in_test("no transaction found", Duration::from_millis(100)).await;
                    continue;
                }
                Some(tx) => tx,
            };

            for input in &tx.input {
                fee += *addresses
                    .get(&input.previous_output.txid)
                    .expect("previous transaction should be known");
            }

            for output in &tx.output {
                fee -= Amount::from_sats(output.value);
            }

            return fee;
        }
    }

    async fn get_tx_block_height(&self, txid: &Txid) -> Option<u64> {
        self.inner
            .read()
            .expect("RwLock poisoned")
            .txid_to_block_height
            .get(txid)
            .map(|height| height.to_owned() as u64)
    }
}

#[async_trait]
impl IBitcoindRpc for FakeBitcoinTest {
    async fn get_network(&self) -> BitcoinRpcResult<bitcoin::Network> {
        Ok(bitcoin::Network::Regtest)
    }

    async fn get_block_count(&self) -> BitcoinRpcResult<u64> {
        Ok(self.inner.read().unwrap().blocks.len() as u64)
    }

    async fn get_block_hash(&self, height: u64) -> BitcoinRpcResult<bitcoin::BlockHash> {
        Ok(self.inner.read().unwrap().blocks[height as usize]
            .header
            .block_hash())
    }

    async fn get_fee_rate(&self, _confirmation_target: u16) -> BitcoinRpcResult<Option<Feerate>> {
        Ok(Some(Feerate { sats_per_kvb: 2000 }))
    }

    async fn submit_transaction(&self, transaction: bitcoin::Transaction) {
        let mut inner = self.inner.write().unwrap();
        inner.pending.push(transaction);

        let mut filtered = BTreeMap::<Vec<OutPoint>, bitcoin::Transaction>::new();

        // Simulate the mempool keeping txs with higher fees (less output)
        // TODO: This looks borked, should remove from `filtered` on higher fee or
        // something, and check per-input anyway. Probably doesn't matter, and I
        // don't want to touch it.
        for tx in &inner.pending {
            match filtered.get(&inputs(tx)) {
                Some(found) if output_sum(tx) > output_sum(found) => {}
                _ => {
                    filtered.insert(inputs(tx), tx.clone());
                }
            }
        }

        inner.pending = filtered.into_values().collect();
    }

    async fn get_tx_block_height(&self, txid: &bitcoin::Txid) -> BitcoinRpcResult<Option<u64>> {
        for (height, block) in self.inner.read().unwrap().blocks.iter().enumerate() {
            if block.txdata.iter().any(|tx| tx.txid() == *txid) {
                return Ok(Some(height as u64));
            }
        }
        Ok(None)
    }

    async fn is_tx_in_block(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
        block_height: u64,
    ) -> BitcoinRpcResult<bool> {
        let block = &self.inner.read().unwrap().blocks[block_height as usize];
        assert!(
            block.block_hash() == *block_hash,
            "Block height for hash does not match expected height"
        );

        Ok(block.txdata.iter().any(|tx| tx.txid() == *txid))
    }

    async fn watch_script_history(&self, _: &ScriptBuf) -> BitcoinRpcResult<()> {
        Ok(())
    }

    async fn get_script_history(
        &self,
        script: &ScriptBuf,
    ) -> BitcoinRpcResult<Vec<bitcoin::Transaction>> {
        let inner = self.inner.read().unwrap();
        let script = inner.scripts.get(script).cloned().unwrap_or_default();
        Ok(script)
    }

    async fn get_txout_proof(&self, txid: bitcoin::Txid) -> BitcoinRpcResult<TxOutProof> {
        let inner = self.inner.read().unwrap();
        let proof = inner.proofs.get(&txid);
        Ok(proof.ok_or(format_err!("No proof stored"))?.clone())
    }
}

fn output_sum(tx: &Transaction) -> u64 {
    tx.output.iter().map(|output| output.value).sum()
}

fn inputs(tx: &Transaction) -> Vec<OutPoint> {
    tx.input.iter().map(|input| input.previous_output).collect()
}
