use std::collections::BTreeMap;
use std::io::Cursor;
use std::ops::Sub;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::{secp256k1, Address, Transaction};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use cln_rpc::model::requests;
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
use cln_rpc::{ClnRpc, Request, Response};
use fedimint_api::config::BitcoindRpcCfg;
use fedimint_api::core::Decoder;
use fedimint_api::encoding::Decodable;
use fedimint_api::Amount;
use fedimint_testing::btc::BitcoinTest;
use fedimint_wallet::txoproof::TxOutProof;
use futures::lock::Mutex;
use lightning_invoice::Invoice;

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
            msatoshi: AmountOrAny::Amount(ClnRpcAmount::from_msat(amount.milli_sat)),
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
        Amount::from_msat(funds)
    }
}

pub struct RealBitcoinTest {
    client: Client,
}

impl RealBitcoinTest {
    const ERROR: &'static str = "Bitcoin RPC returned an error";

    pub fn new(rpc_cfg: &BitcoindRpcCfg) -> Self {
        let client = Client::new(
            &(rpc_cfg.btc_rpc_address),
            Auth::UserPass(rpc_cfg.btc_rpc_user.clone(), rpc_cfg.btc_rpc_pass.clone()),
        )
        .expect(Self::ERROR);

        Self { client }
    }
}

impl BitcoinTest for RealBitcoinTest {
    fn mine_blocks(&self, block_num: u64) {
        self.client
            .generate_to_address(block_num, &self.get_new_address())
            .expect(Self::ERROR);
    }

    fn send_and_mine_block(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> (TxOutProof, Transaction) {
        let id = self
            .client
            .send_to_address(address, amount, None, None, None, None, None, None)
            .expect(Self::ERROR);
        self.mine_blocks(1);

        let tx = self
            .client
            .get_raw_transaction(&id, None)
            .expect(Self::ERROR);
        let proof = TxOutProof::consensus_decode(
            &mut Cursor::new(
                self.client
                    .get_tx_out_proof(&[id], None)
                    .expect(Self::ERROR),
            ),
            &BTreeMap::<_, Decoder>::new(),
        )
        .expect(Self::ERROR);

        (proof, tx)
    }

    fn get_new_address(&self) -> Address {
        self.client.get_new_address(None, None).expect(Self::ERROR)
    }

    fn mine_block_and_get_received(&self, address: &Address) -> Amount {
        self.mine_blocks(1);
        self.client
            .get_received_by_address(address, None)
            .expect(Self::ERROR)
            .into()
    }
}
