use std::ops::Sub;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::secp256k1;
use cln_rpc::model::requests;
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
use cln_rpc::{ClnRpc, Request, Response};
use fedimint_api::Amount;
use futures::lock::Mutex;
use lightning_invoice::Invoice;

use crate::ln::LightningTest;

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
            amount_msat: AmountOrAny::Amount(ClnRpcAmount::from_msat(amount.milli_sat)),
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
