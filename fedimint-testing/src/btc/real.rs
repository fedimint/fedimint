use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::{Address, Transaction, Txid};
use bitcoincore_rpc::{Client, RpcApi};
use fedimint_bitcoind::DynBitcoindRpc;
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::{task, Amount};
use lazy_static::lazy_static;
use url::Url;

use crate::btc::BitcoinTest;

lazy_static! {
    /// Global lock we use to isolate tests that need exclusive control over shared `bitcoind`
    static ref REAL_BITCOIN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::new(());
}

/// Fixture implementing bitcoin node under test by talking to a `bitcoind` with
/// no locking considerations.
///
/// This function assumes the caller already took care of locking
/// considerations).
#[derive(Clone)]
struct RealBitcoinTestNoLock {
    client: Arc<Client>,
    /// RPC used to connect to bitcoind, used for waiting for the RPC to sync
    rpc: DynBitcoindRpc,
}

impl RealBitcoinTestNoLock {
    const ERROR: &'static str = "Bitcoin RPC returned an error";
}

#[async_trait]
impl BitcoinTest for RealBitcoinTestNoLock {
    async fn lock_exclusive(&self) -> Box<dyn BitcoinTest + Send> {
        unimplemented!(
            "You should never try to lock `RealBitcoinTestNoLock`. Lock `RealBitcoinTest` instead"
        )
    }

    async fn mine_blocks(&self, block_num: u64) {
        if let Some(block_hash) = self
            .client
            .generate_to_address(block_num, &self.get_new_address().await)
            .expect(Self::ERROR)
            .last()
        {
            let block = self.client.get_block(block_hash).expect("rpc failed");
            // waits for the rpc client to catch up to bitcoind
            loop {
                let height = self.rpc.get_block_height().await.expect("rpc failed");

                if height >= block.bip34_block_height().expect("has height") {
                    break;
                }
            }
        };
    }

    async fn prepare_funding_wallet(&self) {
        let block_count = self.client.get_block_count().expect("should not fail");
        if block_count < 100 {
            self.mine_blocks(100 - block_count).await;
        }
    }

    async fn send_and_mine_block(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> (TxOutProof, Transaction) {
        let id = self
            .client
            .send_to_address(address, amount, None, None, None, None, None, None)
            .expect(Self::ERROR);
        self.mine_blocks(1).await;

        let tx = self
            .client
            .get_raw_transaction(&id, None)
            .expect(Self::ERROR);
        let proof = TxOutProof::consensus_decode(
            &mut Cursor::new(loop {
                match self.client.get_tx_out_proof(&[id], None) {
                    Ok(o) => break o,
                    Err(e) => {
                        if e.to_string().contains("not yet in block") {
                            // mostly to yield, as we no other yield points
                            task::sleep(Duration::from_millis(1)).await;
                            continue;
                        }
                        panic!("Could not get txoutproof: {e}");
                    }
                }
            }),
            &ModuleDecoderRegistry::default(),
        )
        .expect(Self::ERROR);

        (proof, tx)
    }
    async fn mine_block_and_get_received(&self, address: &Address) -> Amount {
        self.mine_blocks(1).await;
        self.client
            .get_received_by_address(address, None)
            .expect(Self::ERROR)
            .into()
    }

    async fn get_new_address(&self) -> Address {
        self.client.get_new_address(None, None).expect(Self::ERROR)
    }

    async fn get_mempool_tx_fee(&self, txid: &Txid) -> Amount {
        self.client
            .get_mempool_entry(txid)
            .unwrap()
            .fees
            .base
            .into()
    }
}

/// Fixture implementing bitcoin node under test by talking to a `bitcoind` -
/// unlocked version (lock each call separately)
///
/// Default version (and thus the only one with `new`)
pub struct RealBitcoinTest {
    inner: RealBitcoinTestNoLock,
}

impl RealBitcoinTest {
    const ERROR: &'static str = "Bitcoin RPC returned an error";

    pub fn new(url: &Url, rpc: DynBitcoindRpc) -> Self {
        let (host, auth) =
            fedimint_bitcoind::bitcoincore_rpc::from_url_to_url_auth(url).expect("correct url");
        let client = Arc::new(Client::new(&host, auth).expect(Self::ERROR));

        Self {
            inner: RealBitcoinTestNoLock { client, rpc },
        }
    }
}

/// Fixture implementing bitcoin node under test by talking to a `bitcoind` -
/// locked version - locks the global lock during construction
pub struct RealBitcoinTestLocked {
    inner: RealBitcoinTestNoLock,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

#[async_trait]
impl BitcoinTest for RealBitcoinTest {
    async fn lock_exclusive(&self) -> Box<dyn BitcoinTest + Send> {
        Box::new(RealBitcoinTestLocked {
            inner: self.inner.clone(),
            _guard: REAL_BITCOIN_LOCK.lock().await,
        })
    }

    async fn mine_blocks(&self, block_num: u64) {
        let _lock = self.lock_exclusive().await;
        self.inner.mine_blocks(block_num).await;
    }

    async fn prepare_funding_wallet(&self) {
        let _lock = self.lock_exclusive().await;
        self.inner.prepare_funding_wallet().await;
    }

    async fn send_and_mine_block(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> (TxOutProof, Transaction) {
        let _lock = self.lock_exclusive().await;
        self.inner.send_and_mine_block(address, amount).await
    }

    async fn get_new_address(&self) -> Address {
        let _lock = self.lock_exclusive().await;
        self.inner.get_new_address().await
    }

    async fn mine_block_and_get_received(&self, address: &Address) -> Amount {
        let _lock = self.lock_exclusive().await;
        self.inner.mine_block_and_get_received(address).await
    }

    async fn get_mempool_tx_fee(&self, txid: &Txid) -> Amount {
        let _lock = self.lock_exclusive().await;
        self.inner.get_mempool_tx_fee(txid).await
    }
}

#[async_trait]
impl BitcoinTest for RealBitcoinTestLocked {
    async fn lock_exclusive(&self) -> Box<dyn BitcoinTest + Send> {
        panic!("Double-locking would lead to a hang");
    }

    async fn mine_blocks(&self, block_num: u64) {
        let pre = self.inner.client.get_block_count().unwrap();
        self.inner.mine_blocks(block_num).await;
        let post = self.inner.client.get_block_count().unwrap();
        assert_eq!(post - pre, block_num);
    }

    async fn prepare_funding_wallet(&self) {
        self.inner.prepare_funding_wallet().await;
    }

    async fn send_and_mine_block(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> (TxOutProof, Transaction) {
        self.inner.send_and_mine_block(address, amount).await
    }

    async fn get_new_address(&self) -> Address {
        self.inner.get_new_address().await
    }

    async fn mine_block_and_get_received(&self, address: &Address) -> Amount {
        self.inner.mine_block_and_get_received(address).await
    }

    async fn get_mempool_tx_fee(&self, txid: &Txid) -> Amount {
        self.inner.get_mempool_tx_fee(txid).await
    }
}
