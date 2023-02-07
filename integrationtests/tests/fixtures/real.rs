use std::io::Cursor;
use std::ops::Sub;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::{secp256k1, Address, Transaction};
use bitcoincore_rpc::{Client, RpcApi};
use cln_rpc::model::requests;
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
use cln_rpc::{ClnRpc, Request, Response};
use fedimint_api::encoding::Decodable;
use fedimint_api::module::registry::ModuleDecoderRegistry;
use fedimint_api::Amount;
use fedimint_testing::btc::BitcoinTest;
use fedimint_wallet::txoproof::TxOutProof;
use futures::lock::Mutex;
use lazy_static::lazy_static;
use lightning_invoice::Invoice;
use tokio::time::sleep;
use url::Url;

use crate::fixtures::LightningTest;

pub struct RealLightningTest {
    rpc_gateway: Arc<Mutex<ClnRpc>>,
    rpc_other: Arc<Mutex<ClnRpc>>,
    initial_balance: Amount,
    pub gateway_node_pub_key: secp256k1::PublicKey,
}

#[async_trait]
impl LightningTest for RealLightningTest {
    async fn invoice(&self, amount: Amount, expiry_time: Option<u64>) -> Invoice {
        let random: u64 = rand::random();
        let invoice_req = requests::InvoiceRequest {
            amount_msat: AmountOrAny::Amount(ClnRpcAmount::from_msat(amount.msats)),
            description: "".to_string(),
            label: random.to_string(),
            expiry: expiry_time,
            fallbacks: None,
            preimage: None,
            exposeprivatechannels: None,
            cltv: None,
            deschashonly: None,
        };

        let invoice_resp = if let Response::Invoice(data) = self
            .rpc_other
            .lock()
            .await
            .call(Request::Invoice(invoice_req))
            .await
            .unwrap()
        {
            data
        } else {
            panic!("cln-rpc response did not match expected InvoiceResponse")
        };

        Invoice::from_str(&invoice_resp.bolt11).unwrap()
    }

    async fn amount_sent(&self) -> Amount {
        self.initial_balance
            .sub(Self::channel_balance(self.rpc_gateway.clone()).await)
    }

    fn is_shared(&self) -> bool {
        true
    }
}

impl RealLightningTest {
    pub async fn new(socket_gateway: PathBuf, socket_other: PathBuf) -> Self {
        let rpc_other = Arc::new(Mutex::new(ClnRpc::new(socket_other).await.unwrap()));
        let rpc_gateway = Arc::new(Mutex::new(ClnRpc::new(socket_gateway).await.unwrap()));

        let initial_balance = Self::channel_balance(rpc_gateway.clone()).await;

        let getinfo_resp = if let Response::Getinfo(data) = rpc_gateway
            .lock()
            .await
            .call(Request::Getinfo(requests::GetinfoRequest {}))
            .await
            .unwrap()
        {
            data
        } else {
            panic!("cln-rpc response did not match expected GetinfoResponse")
        };

        let gateway_node_pub_key =
            secp256k1::PublicKey::from_str(&getinfo_resp.id.to_string()).unwrap();

        RealLightningTest {
            rpc_gateway,
            rpc_other,
            initial_balance,
            gateway_node_pub_key,
        }
    }

    async fn channel_balance(rpc: Arc<Mutex<ClnRpc>>) -> Amount {
        let listfunds_req = requests::ListfundsRequest { spent: Some(false) };
        let listfunds_resp = if let Response::ListFunds(data) = rpc
            .lock()
            .await
            .call(Request::ListFunds(listfunds_req))
            .await
            .unwrap()
        {
            data
        } else {
            panic!("cln-rpc response did not match expected ListFundsResponse")
        };

        let funds: u64 = listfunds_resp
            .channels
            .iter()
            .filter(|channel| channel.short_channel_id.is_some() && channel.connected)
            .map(|channel| channel.our_amount_msat.msat())
            .sum();
        Amount::from_msats(funds)
    }
}

pub struct RealBitcoinTest {
    client: Arc<Client>,
}

impl RealBitcoinTest {
    const ERROR: &'static str = "Bitcoin RPC returned an error";

    pub fn new(url: &Url) -> Self {
        let (host, auth) =
            fedimint_bitcoind::bitcoincore_rpc::from_url_to_url_auth(url).expect("corrent url");
        let client = Arc::new(Client::new(&host, auth).expect(Self::ERROR));

        Self { client }
    }
}

pub struct RealBitcoinTestLocked {
    inner: RealBitcoinTest,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

lazy_static! {
    static ref REAL_BITCOIN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::new(());
}

#[async_trait]
impl BitcoinTest for RealBitcoinTest {
    async fn lock_exclusive(&self) -> Box<dyn BitcoinTest> {
        Box::new(RealBitcoinTestLocked {
            inner: RealBitcoinTest {
                client: self.client.clone(),
            },
            _guard: REAL_BITCOIN_LOCK.lock().await,
        })
    }

    async fn mine_blocks(&self, block_num: u64) {
        if let Some(block_hash) = self
            .client
            .generate_to_address(block_num, &self.get_new_address().await)
            .expect(Self::ERROR)
            .last()
        {
            // if this is not true, we will have to add some delay mechanism here, because tests expect it
            let _ = self
                .client
                .get_block(block_hash)
                .expect("there should be no delay between block being generated and available");
        };
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
                            sleep(Duration::from_millis(1)).await;
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

    async fn get_new_address(&self) -> Address {
        self.client.get_new_address(None, None).expect(Self::ERROR)
    }

    async fn mine_block_and_get_received(&self, address: &Address) -> Amount {
        self.mine_blocks(1).await;
        self.client
            .get_received_by_address(address, None)
            .expect(Self::ERROR)
            .into()
    }
}
#[async_trait]
impl BitcoinTest for RealBitcoinTestLocked {
    async fn lock_exclusive(&self) -> Box<dyn BitcoinTest> {
        panic!("Double-locking would lead to a hang");
    }

    async fn mine_blocks(&self, block_num: u64) {
        self.inner.mine_blocks(block_num).await
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
}
