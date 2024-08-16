use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use bitcoin::{Address, Transaction, Txid};
use bitcoincore_rpc::{Client, RpcApi};
use fedimint_bitcoind::DynBitcoindRpc;
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{block_in_place, sleep_in_test};
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::SafeUrl;
use fedimint_core::{task, Amount};
use fedimint_logging::LOG_TEST;
use tracing::{debug, trace};

use crate::btc::BitcoinTest;

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
    async fn lock_exclusive(&self) -> Box<dyn BitcoinTest + Send + Sync> {
        unimplemented!(
            "You should never try to lock `RealBitcoinTestNoLock`. Lock `RealBitcoinTest` instead"
        )
    }

    async fn mine_blocks(&self, block_num: u64) -> Vec<bitcoin::BlockHash> {
        let mined_block_hashes = self
            .client
            .generate_to_address(block_num, &self.get_new_address().await)
            .expect(Self::ERROR);

        if let Some(block_hash) = mined_block_hashes.last() {
            let last_mined_block = self
                .client
                .get_block_header_info(block_hash)
                .expect("rpc failed");
            let expected_block_count = last_mined_block.height as u64 + 1;
            // waits for the rpc client to catch up to bitcoind
            loop {
                let current_block_count = self.rpc.get_block_count().await.expect("rpc failed");
                if current_block_count < expected_block_count {
                    debug!(
                        target: LOG_TEST,
                        ?block_num,
                        ?expected_block_count,
                        ?current_block_count,
                        "Waiting for blocks to be mined"
                    );
                    sleep_in_test("waiting for blocks to be mined", Duration::from_millis(200))
                        .await;
                } else {
                    debug!(
                        target: LOG_TEST,
                        ?block_num,
                        ?expected_block_count,
                        ?current_block_count,
                        "Mined blocks"
                    );
                    break;
                }
            }
        };

        mined_block_hashes
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
        let mined_block_hashes = self.mine_blocks(1).await;
        let mined_block_hash = mined_block_hashes.first().expect("mined a block");

        let tx = self
            .client
            .get_raw_transaction(&id, Some(mined_block_hash))
            .expect(Self::ERROR);
        let proof = TxOutProof::consensus_decode(
            &mut Cursor::new(loop {
                match self.client.get_tx_out_proof(&[id], None) {
                    Ok(o) => break o,
                    Err(e) => {
                        if e.to_string().contains("not yet in block") {
                            // mostly to yield, as we no other yield points
                            task::sleep_in_test("not yet in block", Duration::from_millis(1)).await;
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
        self.client
            .get_new_address(None, None)
            .expect(Self::ERROR)
            .require_network()
    }

    async fn get_mempool_tx_fee(&self, txid: &Txid) -> Amount {
        loop {
            if let Ok(tx) = self.client.get_mempool_entry(txid) {
                return tx.fees.base.into();
            }

            sleep_in_test("could not get mempool tx fee", Duration::from_millis(100)).await;
        }
    }

    async fn get_tx_block_height(&self, txid: &Txid) -> Option<u64> {
        let current_block_count = self
            .client
            .get_block_count()
            .expect("failed to fetch chain tip");
        (0..=current_block_count)
            .position(|height| {
                let block_hash = self
                    .client
                    .get_block_hash(height)
                    .expect("failed to fetch block hash");

                self.client
                    .get_block_info(&block_hash)
                    .expect("failed to fetch block info")
                    .tx
                    .iter()
                    .any(|id| id == txid)
            })
            .map(|height| height as u64)
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

    pub fn new(url: &SafeUrl, rpc: DynBitcoindRpc) -> Self {
        let (host, auth) =
            fedimint_bitcoind::bitcoincore::from_url_to_url_auth(url).expect("correct url");
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
    _guard: fs_lock::FileLock,
}

#[async_trait]
impl BitcoinTest for RealBitcoinTest {
    async fn lock_exclusive(&self) -> Box<dyn BitcoinTest + Send + Sync> {
        trace!("Trying to acquire global bitcoin lock");
        let _guard = block_in_place(|| {
            let lock_file_path = std::env::temp_dir().join("fm-test-bitcoind-lock");
            fs_lock::FileLock::new_exclusive(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&lock_file_path)
                    .with_context(|| format!("Failed to open {}", lock_file_path.display()))?,
            )
            .context("Failed to acquire exclusive lock file")
        })
        .expect("Failed to lock");
        trace!("Acquired global bitcoin lock");
        Box::new(RealBitcoinTestLocked {
            inner: self.inner.clone(),
            _guard,
        })
    }

    async fn mine_blocks(&self, block_num: u64) -> Vec<bitcoin::BlockHash> {
        let _lock = self.lock_exclusive().await;
        self.inner.mine_blocks(block_num).await
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

    async fn get_tx_block_height(&self, txid: &Txid) -> Option<u64> {
        let _lock = self.lock_exclusive().await;
        self.inner.get_tx_block_height(txid).await
    }
}

#[async_trait]
impl BitcoinTest for RealBitcoinTestLocked {
    async fn lock_exclusive(&self) -> Box<dyn BitcoinTest + Send + Sync> {
        panic!("Double-locking would lead to a hang");
    }

    async fn mine_blocks(&self, block_num: u64) -> Vec<bitcoin::BlockHash> {
        let pre = self.inner.client.get_block_count().unwrap();
        let mined_block_hashes = self.inner.mine_blocks(block_num).await;
        let post = self.inner.client.get_block_count().unwrap();
        assert_eq!(post - pre, block_num);
        mined_block_hashes
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

    async fn get_tx_block_height(&self, txid: &Txid) -> Option<u64> {
        self.inner.get_tx_block_height(txid).await
    }
}
