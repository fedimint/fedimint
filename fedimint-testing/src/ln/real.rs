use std::ops::Sub;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::{env, fmt};

use async_trait::async_trait;
use bitcoin::secp256k1;
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
use cln_rpc::{model, ClnRpc, Request, Response};
use fedimint_core::task::TaskGroup;
use fedimint_core::Amount;
use lightning_invoice::Invoice;
use ln_gateway::gatewaylnrpc::{
    GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcResponse, PayInvoiceRequest,
    PayInvoiceResponse,
};
use ln_gateway::lnd::GatewayLndClient;
use ln_gateway::lnrpc_client::{ILnRpcClient, NetworkLnRpcClient, RouteHtlcStream};
use ln_gateway::GatewayError;
use tokio::sync::{Mutex, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic_lnd::lnrpc::{GetInfoRequest, Invoice as LndInvoice, ListChannelsRequest};
use tonic_lnd::{connect, LndClient};
use tracing::info;
use url::Url;

use crate::ln::LightningTest;

#[derive(Clone)]
pub struct ClnLightningTest {
    rpc_cln: Arc<Mutex<ClnRpc>>,
    initial_balance: Amount,
    pub node_pub_key: secp256k1::PublicKey,
    lnrpc: Arc<RwLock<dyn ILnRpcClient>>,
}

impl fmt::Debug for ClnLightningTest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ClnLightningTest")
            .field("initial_balance", &self.initial_balance)
            .field("node_pub_key", &self.node_pub_key)
            .finish()
    }
}

#[async_trait]
impl LightningTest for ClnLightningTest {
    async fn invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Invoice> {
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

    async fn amount_sent(&self) -> Amount {
        let current_balance = Self::channel_balance(self.rpc_cln.clone()).await;
        self.initial_balance.sub(current_balance)
    }

    fn is_shared(&self) -> bool {
        true
    }
}

#[async_trait]
impl ILnRpcClient for ClnLightningTest {
    async fn info(&self) -> Result<GetNodeInfoResponse, GatewayError> {
        self.lnrpc.read().await.info().await
    }

    async fn routehints(&self) -> Result<GetRouteHintsResponse, GatewayError> {
        self.lnrpc.read().await.routehints().await
    }

    async fn pay(&self, invoice: PayInvoiceRequest) -> Result<PayInvoiceResponse, GatewayError> {
        self.lnrpc.read().await.pay(invoice).await
    }

    async fn route_htlcs<'a>(
        &mut self,
        events: ReceiverStream<InterceptHtlcResponse>,
        task_group: &mut TaskGroup,
    ) -> Result<RouteHtlcStream<'a>, GatewayError> {
        self.lnrpc
            .write()
            .await
            .route_htlcs(events, task_group)
            .await
    }
}

impl ClnLightningTest {
    pub async fn new(dir: &str) -> ClnLightningTest {
        let socket_cln = PathBuf::from(dir).join("cln/regtest/lightning-rpc");
        let rpc_cln = Arc::new(Mutex::new(ClnRpc::new(socket_cln).await.unwrap()));

        let initial_balance = Self::channel_balance(rpc_cln.clone()).await;
        let node_pub_key = Self::pubkey(rpc_cln.clone()).await;

        let lnrpc_addr = env::var("FM_GATEWAY_LIGHTNING_ADDR")
            .expect("FM_GATEWAY_LIGHTNING_ADDR not set")
            .parse::<Url>()
            .expect("Invalid FM_GATEWAY_LIGHTNING_ADDR");
        let lnrpc: Arc<RwLock<dyn ILnRpcClient>> = Arc::new(RwLock::new(
            NetworkLnRpcClient::new(lnrpc_addr).await.unwrap(),
        ));

        ClnLightningTest {
            rpc_cln,
            initial_balance,
            node_pub_key,
            lnrpc,
        }
    }

    async fn pubkey(rpc: Arc<Mutex<ClnRpc>>) -> secp256k1::PublicKey {
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

    async fn channel_balance(rpc: Arc<Mutex<ClnRpc>>) -> Amount {
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
}

#[derive(Clone)]
pub struct LndLightningTest {
    rpc_lnd: Arc<Mutex<LndClient>>,
    initial_balance: Amount,
    pub node_pub_key: secp256k1::PublicKey,
    lnrpc: Arc<RwLock<dyn ILnRpcClient>>,
}

#[async_trait]
impl LightningTest for LndLightningTest {
    async fn invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Invoice> {
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

    async fn amount_sent(&self) -> Amount {
        let current_balance = Self::channel_balance(self.rpc_lnd.clone()).await;
        self.initial_balance.sub(current_balance)
    }

    fn is_shared(&self) -> bool {
        true
    }
}

impl fmt::Debug for LndLightningTest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LndLightningTest")
            .field("initial_balance", &self.initial_balance)
            .field("node_pub_key", &self.node_pub_key)
            .finish()
    }
}

#[async_trait]
impl ILnRpcClient for LndLightningTest {
    async fn info(&self) -> Result<GetNodeInfoResponse, GatewayError> {
        self.lnrpc.read().await.info().await
    }

    async fn routehints(&self) -> Result<GetRouteHintsResponse, GatewayError> {
        self.lnrpc.read().await.routehints().await
    }

    async fn pay(&self, invoice: PayInvoiceRequest) -> Result<PayInvoiceResponse, GatewayError> {
        self.lnrpc.read().await.pay(invoice).await
    }

    async fn route_htlcs<'a>(
        &mut self,
        events: ReceiverStream<InterceptHtlcResponse>,
        task_group: &mut TaskGroup,
    ) -> Result<RouteHtlcStream<'a>, GatewayError> {
        self.lnrpc
            .write()
            .await
            .route_htlcs(events, task_group)
            .await
    }
}

impl LndLightningTest {
    pub async fn new() -> LndLightningTest {
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

        let initial_balance = Self::channel_balance(rpc_lnd.clone()).await;
        let node_pub_key = Self::pubkey(rpc_lnd.clone()).await;

        let gateway_lnd_client = GatewayLndClient::new(lnd_rpc_addr, lnd_tls_cert, lnd_macaroon)
            .await
            .unwrap();
        let lnrpc = Arc::new(RwLock::new(gateway_lnd_client));
        LndLightningTest {
            rpc_lnd,
            initial_balance,
            node_pub_key,
            lnrpc,
        }
    }

    async fn pubkey(rpc: Arc<Mutex<LndClient>>) -> secp256k1::PublicKey {
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

    async fn channel_balance(rpc: Arc<Mutex<LndClient>>) -> Amount {
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
