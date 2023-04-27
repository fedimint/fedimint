use std::env;
use std::ops::Sub;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::secp256k1;
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
use cln_rpc::{model, ClnRpc, Request, Response};
use fedimint_core::Amount;
use lightning_invoice::Invoice;
use tokio::sync::Mutex;
use tonic_lnd::lnrpc::{GetInfoRequest, Invoice as LndInvoice, ListChannelsRequest};
use tonic_lnd::{connect, LndClient};
use tracing::info;

use crate::ln::{GatewayNode, LightningTest};

#[derive(Clone)]
pub struct RealLightningTest {
    rpc_cln: Arc<Mutex<ClnRpc>>,
    rpc_lnd: Arc<Mutex<LndClient>>,
    initial_balance: Amount,
    // Which lightning node to use as the gateway?
    gateway_node: GatewayNode,
    pub gateway_node_pub_key: secp256k1::PublicKey,
}

#[async_trait]
impl LightningTest for RealLightningTest {
    async fn invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Invoice> {
        match self.gateway_node {
            // If we're using CLN as the gateway, use LND to fetch an invoice
            GatewayNode::Cln => {
                info!("fetching invoice from lnd");
                let mut lnd_rpc = self.rpc_lnd.lock().await;
                let tonic_invoice = match expiry_time {
                    Some(expiry) => LndInvoice {
                        value_msat: amount.msats as i64,
                        expiry: expiry as i64,
                        ..Default::default()
                    },
                    None => LndInvoice {
                        value_msat: amount.msats as i64,
                        ..Default::default()
                    },
                };
                let invoice_resp = lnd_rpc
                    .lightning()
                    .add_invoice(tonic_invoice)
                    .await
                    .unwrap()
                    .into_inner();

                Ok(Invoice::from_str(&invoice_resp.payment_request).unwrap())
            }
            // If we're using LND as the gateway, use CLN to fetch an invoice
            GatewayNode::Lnd => {
                info!("fetching invoice from cln");
                let random: u64 = rand::random();
                let invoice_req = model::InvoiceRequest {
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
                    .rpc_cln
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

                Ok(Invoice::from_str(&invoice_resp.bolt11).unwrap())
            }
        }
    }

    async fn amount_sent(&self) -> Amount {
        let current_balance = match self.gateway_node {
            GatewayNode::Cln => Self::channel_balance_cln(self.rpc_cln.clone()).await,
            GatewayNode::Lnd => Self::channel_balance_lnd(self.rpc_lnd.clone()).await,
        };
        self.initial_balance.sub(current_balance)
    }

    fn is_shared(&self) -> bool {
        true
    }
}

impl RealLightningTest {
    pub async fn new(dir: &str, gateway_node: &GatewayNode) -> RealLightningTest {
        // lightning - we create one LND RPC client, and one CLN RPC client. one will be
        // used as the gateway's lightning node, and the other is an external node
        // outside the federation that can be used to test lightnining
        // payments through the gateway
        let socket_cln = PathBuf::from(dir).join("cln/regtest/lightning-rpc");
        let rpc_cln = Arc::new(Mutex::new(ClnRpc::new(socket_cln).await.unwrap()));
        let lnd_rpc_addr = env::var("FM_LND_RPC_ADDR").unwrap();
        let lnd_macaroon = env::var("FM_LND_MACAROON").unwrap();
        let lnd_tls_cert = env::var("FM_LND_TLS_CERT").unwrap();
        let lnd_client = connect(
            lnd_rpc_addr.clone(),
            lnd_tls_cert.clone(),
            lnd_macaroon.clone(),
        )
        .await
        .unwrap();
        let rpc_lnd = Arc::new(Mutex::new(lnd_client.clone()));
        RealLightningTest::from_clients(rpc_cln, rpc_lnd, gateway_node.clone()).await
    }

    async fn from_clients(
        rpc_cln: Arc<Mutex<ClnRpc>>,
        rpc_lnd: Arc<Mutex<LndClient>>,
        gateway_node: GatewayNode,
    ) -> Self {
        let (initial_balance, gateway_node_pub_key) = match gateway_node {
            GatewayNode::Cln => (
                Self::channel_balance_cln(rpc_cln.clone()).await,
                Self::pubkey_cln(rpc_cln.clone()).await,
            ),
            GatewayNode::Lnd => (
                Self::channel_balance_lnd(rpc_lnd.clone()).await,
                Self::pubkey_lnd(rpc_lnd.clone()).await,
            ),
        };

        RealLightningTest {
            rpc_cln,
            rpc_lnd,
            initial_balance,
            gateway_node,
            gateway_node_pub_key,
        }
    }

    async fn pubkey_cln(rpc: Arc<Mutex<ClnRpc>>) -> secp256k1::PublicKey {
        info!("fetching pubkey from cln");
        if let Response::Getinfo(get_info) = rpc
            .lock()
            .await
            .call(Request::Getinfo(model::GetinfoRequest {}))
            .await
            .unwrap()
        {
            secp256k1::PublicKey::from_str(&get_info.id.to_string()).unwrap()
        } else {
            panic!("cln-rpc response did not match expected GetinfoResponse")
        }
    }
    async fn pubkey_lnd(rpc: Arc<Mutex<LndClient>>) -> secp256k1::PublicKey {
        info!("fetching pubkey from lnd");
        let info = rpc
            .lock()
            .await
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .expect("failed to get info")
            .into_inner();
        let pub_key: secp256k1::PublicKey = info.identity_pubkey.parse().expect("invalid pubkey");
        pub_key
    }

    async fn channel_balance_cln(rpc: Arc<Mutex<ClnRpc>>) -> Amount {
        info!("fetching balance from cln");
        let listfunds_req = model::ListfundsRequest { spent: Some(false) };
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
    async fn channel_balance_lnd(rpc: Arc<Mutex<LndClient>>) -> Amount {
        info!("fetching balance from lnd");
        let list_channels = rpc
            .lock()
            .await
            .lightning()
            .list_channels(ListChannelsRequest {
                active_only: true,
                ..Default::default()
            })
            .await
            .expect("failed to get info")
            .into_inner();

        let funds: i64 = list_channels
            .channels
            .iter()
            .map(|channel| channel.local_balance)
            .sum();
        Amount::from_msats(funds as u64)
    }
}
