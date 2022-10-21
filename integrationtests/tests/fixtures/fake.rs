use std::iter::repeat;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{
    secp256k1, Address, Block, BlockHash, BlockHeader, KeyPair, Network, PackedLockTime,
    Transaction, TxOut,
};
use fedimint_api::bitcoin_rpc::IBitcoindRpc;
use fedimint_api::bitcoin_rpc::Result as BitcoinRpcResult;
use fedimint_api::{Amount, Feerate};
use fedimint_server::modules::ln::contracts::Preimage;
use fedimint_wallet::txoproof::TxOutProof;
use lightning::ln::PaymentSecret;
use lightning_invoice::{Currency, Invoice, InvoiceBuilder, DEFAULT_EXPIRY_TIME};
use ln_gateway::ln::{LightningError, LnRpc};
use rand::rngs::OsRng;

use crate::fixtures::{BitcoinTest, LightningTest};

#[derive(Clone, Debug)]
pub struct FakeLightningTest {
    pub preimage: Preimage,
    pub gateway_node_pub_key: secp256k1::PublicKey,
    gateway_node_sec_key: secp256k1::SecretKey,
    amount_sent: Arc<Mutex<u64>>,
}

impl FakeLightningTest {
    pub fn new() -> Self {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let kp = KeyPair::new(&ctx, &mut OsRng);
        let amount_sent = Arc::new(Mutex::new(0));

        FakeLightningTest {
            preimage: Preimage([1; 32]),
            gateway_node_sec_key: SecretKey::from_keypair(&kp),
            gateway_node_pub_key: PublicKey::from_keypair(&kp),
            amount_sent,
        }
    }
}

#[async_trait]
impl LightningTest for FakeLightningTest {
    async fn invoice(&self, amount: Amount, expiry_time: Option<u64>) -> Invoice {
        let ctx = bitcoin::secp256k1::Secp256k1::new();

        InvoiceBuilder::new(Currency::Regtest)
            .description("".to_string())
            .payment_hash(sha256::Hash::hash(&self.preimage.0))
            .current_timestamp()
            .min_final_cltv_expiry(0)
            .payment_secret(PaymentSecret([0; 32]))
            .amount_milli_satoshis(amount.milli_sat)
            .expiry_time(Duration::from_secs(
                expiry_time.unwrap_or(DEFAULT_EXPIRY_TIME),
            ))
            .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &self.gateway_node_sec_key))
            .unwrap()
    }

    async fn amount_sent(&self) -> Amount {
        Amount::from_msat(*self.amount_sent.lock().unwrap())
    }
}

#[async_trait]
impl LnRpc for FakeLightningTest {
    async fn pay(
        &self,
        invoice_str: &str,
        _max_delay: u64,
        _max_fee_percent: f64,
    ) -> Result<Preimage, LightningError> {
        let invoice: Invoice = invoice_str.parse().unwrap();
        *self.amount_sent.lock().unwrap() += invoice.amount_milli_satoshis().unwrap();

        Ok(self.preimage.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FakeBitcoinTest {
    blocks: Arc<Mutex<Vec<Block>>>,
    pending: Arc<Mutex<Vec<Transaction>>>,
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
        Amount::from_sat(sats)
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
