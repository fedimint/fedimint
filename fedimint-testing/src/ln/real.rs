use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::{env, fmt};

use async_trait::async_trait;
use bitcoin::{secp256k1, Network};
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
use cln_rpc::{model, ClnRpc, Request, Response};
use fedimint_core::task::TaskGroup;
use fedimint_core::Amount;
use ldk_node::io::SqliteStore;
use ldk_node::{Builder, Event, LogLevel, NetAddress, Node};
use lightning_invoice::Invoice;
use ln_gateway::gatewaylnrpc::{
    EmptyResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcResponse,
    PayInvoiceRequest, PayInvoiceResponse,
};
use ln_gateway::lnd::GatewayLndClient;
use ln_gateway::lnrpc_client::{
    ILnRpcClient, LightningRpcError, NetworkLnRpcClient, RouteHtlcStream,
};
use secp256k1::PublicKey;
use tokio::sync::Mutex;
use tonic_lnd::lnrpc::{GetInfoRequest, Invoice as LndInvoice, ListChannelsRequest};
use tonic_lnd::{connect, LndClient};
use tracing::{error, info, warn};
use url::Url;

use crate::btc::BitcoinTest;
use crate::ln::LightningTest;

const DEFAULT_ESPLORA_SERVER: &str = "http://127.0.0.1:50002";

pub struct ClnLightningTest {
    rpc_cln: Arc<Mutex<ClnRpc>>,
    initial_balance: Amount,
    pub node_pub_key: secp256k1::PublicKey,
    lnrpc: Box<dyn ILnRpcClient>,
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

    fn is_shared(&self) -> bool {
        true
    }

    fn listening_address(&self) -> String {
        "127.0.0.1:9000".to_string()
    }
}

#[async_trait]
impl ILnRpcClient for ClnLightningTest {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        self.lnrpc.info().await
    }

    async fn routehints(&self) -> Result<GetRouteHintsResponse, LightningRpcError> {
        self.lnrpc.routehints().await
    }

    async fn pay(
        &self,
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        self.lnrpc.pay(invoice).await
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        self.lnrpc.route_htlcs(task_group).await
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        self.lnrpc.complete_htlc(htlc).await
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
        let lnrpc: Box<dyn ILnRpcClient> = Box::new(NetworkLnRpcClient::new(lnrpc_addr).await);

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

pub struct LndLightningTest {
    rpc_lnd: Arc<Mutex<LndClient>>,
    initial_balance: Amount,
    pub node_pub_key: secp256k1::PublicKey,
    lnrpc: Box<dyn ILnRpcClient>,
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

    fn is_shared(&self) -> bool {
        true
    }

    fn listening_address(&self) -> String {
        "127.0.0.1:9734".to_string()
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
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        self.lnrpc.info().await
    }

    async fn routehints(&self) -> Result<GetRouteHintsResponse, LightningRpcError> {
        self.lnrpc.routehints().await
    }

    async fn pay(
        &self,
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        self.lnrpc.pay(invoice).await
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        self.lnrpc.route_htlcs(task_group).await
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        self.lnrpc.complete_htlc(htlc).await
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

        let gateway_lnd_client =
            GatewayLndClient::new(lnd_rpc_addr, lnd_tls_cert, lnd_macaroon, None).await;
        let lnrpc = Box::new(gateway_lnd_client);
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

#[derive(Debug)]
pub struct LdkLightningTest {
    node_pub_key: PublicKey,
    alias: String,
    ldk_node_sender: Arc<Mutex<std::sync::mpsc::Sender<LdkMessage>>>,
    listening_address: String,
}

#[derive(Debug)]
enum LdkMessage {
    InvoiceRequest {
        amount_msat: u64,
        description: String,
        expiry_secs: u32,
        response_sender: std::sync::mpsc::Sender<LdkMessage>,
    },
    InvoiceResponse {
        invoice: Invoice,
    },
    OpenChannelRequest {
        node_id: PublicKey,
        amount: u64,
        connect_address: NetAddress,
        response_sender: std::sync::mpsc::Sender<LdkMessage>,
    },
    MineBlocksResponse,
    OpenChannelResponse,
    StopRequest {
        response_sender: std::sync::mpsc::Sender<LdkMessage>,
    },
    StopResponse,
    PayInvoiceRequest {
        invoice: String,
        response_sender: std::sync::mpsc::Sender<LdkMessage>,
    },
    PayInvoiceSuccessResponse {
        preimage: [u8; 32],
    },
    PayInvoiceFailureResponse,
}

impl LdkLightningTest {
    pub async fn new(
        db_path: PathBuf,
        bitcoin: Arc<dyn BitcoinTest>,
    ) -> Result<LdkLightningTest, LightningRpcError> {
        let mut builder = Builder::new();
        builder.set_network(Network::Regtest);
        // TODO: Set unique port
        builder.set_listening_address(
            NetAddress::from_str("0.0.0.0:9091").expect("Couldnt parse listening address"),
        );
        builder.set_storage_dir_path(db_path.to_string_lossy().to_string());
        builder.set_esplora_server(DEFAULT_ESPLORA_SERVER.to_string());
        builder.set_log_level(LogLevel::Debug);
        let node = builder.build().map_err(|e| {
            error!("Failed to build LDK Node: {e:?}");
            LightningRpcError::FailedToConnect
        })?;
        let pub_key = node.node_id();

        // Add 1 BTC to LDK's onchain wallet so it can open channels
        let address = node.new_onchain_address().map_err(|e| {
            error!("Failed to get onchain address from LDK Node: {e:?}");
            LightningRpcError::FailedToConnect
        })?;
        let btc_amount = bitcoin::Amount::from_sat(100000000);
        bitcoin.send_and_mine_block(&address, btc_amount).await;
        bitcoin.mine_blocks(1).await;

        let (sender, receiver) = std::sync::mpsc::channel::<LdkMessage>();
        node.start().map_err(|e| {
            error!("Failed to start LDK Node: {e:?}");
            LightningRpcError::FailedToConnect
        })?;

        loop {
            let onchain_amount = node.total_onchain_balance_sats().map_err(|e| {
                error!("Failed to get LDK onchain balance: {e:?}");
                LightningRpcError::FailedToConnect
            })?;

            if btc_amount.to_sat() == onchain_amount {
                break;
            }

            fedimint_core::task::sleep(std::time::Duration::from_secs(1)).await;

            info!("LDK Node didn't find onchain balance, syncing wallet...");
            node.sync_wallets().map_err(|e| {
                error!("Failed to sync LDK Node onchain wallet: {e:?}");
                LightningRpcError::FailedToConnect
            })?;
        }

        Self::spawn_ldk_event_loop(node, receiver).await;

        Ok(LdkLightningTest {
            node_pub_key: pub_key,
            alias: format!("LDKNode-{}", rand::random::<u64>()),
            ldk_node_sender: Arc::new(Mutex::new(sender)),
            listening_address: "127.0.0.1:9091".to_string(),
        })
    }

    async fn spawn_ldk_event_loop(
        node: Node<SqliteStore>,
        receiver: std::sync::mpsc::Receiver<LdkMessage>,
    ) {
        tokio::task::spawn_blocking(move || {
            loop {
                let request = receiver.recv().expect("Failed to receive Ldk Message");
                match request {
                    LdkMessage::InvoiceRequest {
                        amount_msat,
                        description,
                        expiry_secs,
                        response_sender,
                    } => {
                        let ldk_invoice = node
                            .receive_payment(amount_msat, description.as_str(), expiry_secs)
                            .expect("LDK Node failed to create invoice");
                        let invoice =
                            lightning_invoice::Invoice::from_str(ldk_invoice.to_string().as_str())
                                .expect("Failed to create lightning_invoice");
                        response_sender
                            .send(LdkMessage::InvoiceResponse { invoice })
                            .expect("Failed to send InvoiceResponse");
                    }
                    LdkMessage::OpenChannelRequest {
                        node_id,
                        amount,
                        connect_address,
                        response_sender,
                    } => {
                        // Always push half of the balance to the other side so we have a balanced
                        // channel initially
                        let amount_push = amount / 2;
                        node.connect_open_channel(
                            node_id,
                            connect_address.clone(),
                            amount,
                            Some(amount_push * 1000),
                            None,
                            true,
                        )
                        .expect("LDK Node Failed to open channel");

                        // Wait for ChannelReady event
                        loop {
                            let event = node.wait_next_event();
                            match event {
                                Event::ChannelPending { .. } => {
                                    node.event_handled();
                                    response_sender
                                        .send(LdkMessage::MineBlocksResponse)
                                        .expect("Failed to send MineBlocksResponse");
                                }
                                Event::ChannelReady { .. } => {
                                    node.event_handled();
                                    break;
                                }
                                _ => {
                                    panic!("Received unexpected event while opening the channel to {connect_address:?}. Event: {event:?}");
                                }
                            }
                        }

                        response_sender
                            .send(LdkMessage::OpenChannelResponse)
                            .expect("Failed to send OpenChannelResponse");
                    }
                    LdkMessage::StopRequest { response_sender } => {
                        node.stop().expect("Failed to stop LDK Node");
                        response_sender
                            .send(LdkMessage::StopResponse)
                            .expect("Failed to send StopResponse");
                        break;
                    }
                    LdkMessage::PayInvoiceRequest {
                        invoice,
                        response_sender,
                    } => {
                        node.send_payment(
                            &ldk_node::lightning_invoice::Invoice::from_str(invoice.as_str())
                                .expect("SendPayment could not parse invoice"),
                        )
                        .expect("Failed to send payment to invoice");
                        loop {
                            let event = node.wait_next_event();
                            match event {
                                Event::PaymentFailed { payment_hash: _ } => {
                                    node.event_handled();
                                    response_sender
                                        .send(LdkMessage::PayInvoiceFailureResponse)
                                        .expect("Failed to send PayInvoiceFailureResponse");
                                    break;
                                }
                                Event::PaymentSuccessful { payment_hash } => {
                                    node.event_handled();
                                    // PaymentSuccess doesn't return the preimage?
                                    response_sender
                                        .send(LdkMessage::PayInvoiceSuccessResponse {
                                            preimage: payment_hash.0,
                                        })
                                        .expect("Failed to send PayInvoiceSuccessResponse");
                                    break;
                                }
                                _ => {
                                    panic!(
                                        "Received unexpected event while paying invoice: {event:?}"
                                    );
                                }
                            }
                        }
                    }
                    _ => {
                        warn!("Unsupported LdkMessage received: {request:?}");
                    }
                }
            }
        });
    }

    pub async fn open_channel(
        &self,
        amount: Amount,
        node_pubkey: PublicKey,
        address: String,
        bitcoin: Box<dyn BitcoinTest + Send + Sync>,
    ) -> anyhow::Result<()> {
        let (sender, receiver) = std::sync::mpsc::channel::<LdkMessage>();
        let connect_address = NetAddress::from_str(address.as_str()).map_err(|e| {
            LightningRpcError::FailedToOpenChannel {
                failure_reason: format!("Failed to parse connect address: {e:?}"),
            }
        })?;
        self.ldk_node_sender
            .lock()
            .await
            .send(LdkMessage::OpenChannelRequest {
                node_id: node_pubkey,
                amount: amount.msats,
                connect_address,
                response_sender: sender,
            })
            .map_err(|e| LightningRpcError::FailedToOpenChannel {
                failure_reason: format!("Failed to open channel {e:?}"),
            })?;

        loop {
            let response = receiver
                .recv()
                .map_err(|e| LightningRpcError::FailedToOpenChannel {
                    failure_reason: format!("Failed to open channel {e:?}"),
                })?;

            match response {
                LdkMessage::MineBlocksResponse => {
                    bitcoin.mine_blocks(3).await;
                }
                LdkMessage::OpenChannelResponse => {
                    return Ok(());
                }
                _ => {
                    panic!("Received unexpected LdkMessage: {response:?}");
                }
            }
        }
    }
}

impl Drop for LdkLightningTest {
    fn drop(&mut self) {
        fedimint_core::task::block_in_place(|| {
            let (sender, receiver) = std::sync::mpsc::channel::<LdkMessage>();
            self.ldk_node_sender
                .blocking_lock()
                .send(LdkMessage::StopRequest {
                    response_sender: sender,
                })
                .expect("Failed to send Drop message to LDK node");
            // Wait for the response
            receiver.recv().expect("Failed to receive StopResponse");
        });
    }
}

#[async_trait]
impl ILnRpcClient for LdkLightningTest {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        Ok(GetNodeInfoResponse {
            pub_key: self.node_pub_key.serialize().to_vec(),
            alias: self.alias.clone(),
        })
    }

    async fn routehints(&self) -> Result<GetRouteHintsResponse, LightningRpcError> {
        unimplemented!("Unsupported: we dont currently support route hints for LDK Node")
    }

    async fn pay(
        &self,
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let (sender, receiver) = std::sync::mpsc::channel::<LdkMessage>();
        self.ldk_node_sender
            .lock()
            .await
            .send(LdkMessage::PayInvoiceRequest {
                invoice: invoice.invoice,
                response_sender: sender,
            })
            .map_err(|e| LightningRpcError::FailedPayment {
                failure_reason: format!("LDK Node failed to pay invoice: {e:?}"),
            })?;

        let response = receiver
            .recv()
            .map_err(|e| LightningRpcError::FailedPayment {
                failure_reason: format!("LDK Node failed to pay invoice: {e:?}"),
            })?;
        match response {
            LdkMessage::PayInvoiceFailureResponse => {
                return Err(LightningRpcError::FailedPayment {
                    failure_reason: "LDK Node failed to pay invoice".to_string(),
                });
            }
            LdkMessage::PayInvoiceSuccessResponse { preimage } => Ok(PayInvoiceResponse {
                preimage: preimage.to_vec(),
            }),
            _ => {
                panic!("Received unexpected LdkMessage: {response:?}");
            }
        }
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        _task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        unimplemented!("Unsupported: we dont currently support HTLC interception for LDK Node");
    }

    async fn complete_htlc(
        &self,
        _htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        unimplemented!("Unsupported: we dont currently support HTLC interception for LDK Node");
    }
}

#[async_trait]
impl LightningTest for LdkLightningTest {
    async fn invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Invoice> {
        let (sender, receiver) = std::sync::mpsc::channel::<LdkMessage>();
        self.ldk_node_sender
            .lock()
            .await
            .send(LdkMessage::InvoiceRequest {
                amount_msat: amount.msats,
                description: "LDK Description".to_string(),
                expiry_secs: expiry_time.unwrap_or(600) as u32,
                response_sender: sender,
            })
            .map_err(|e| LightningRpcError::FailedToGetInvoice {
                failure_reason: format!("Failed to get invoice: {e:?}"),
            })?;

        let response = receiver
            .recv()
            .map_err(|e| LightningRpcError::FailedToGetInvoice {
                failure_reason: format!("Failed to get invoice: {e:?}"),
            })?;
        match response {
            LdkMessage::InvoiceResponse { invoice } => Ok(invoice),
            _ => {
                panic!("Received unexpected LdkMessage: {response:?}");
            }
        }
    }

    fn is_shared(&self) -> bool {
        true
    }

    fn listening_address(&self) -> String {
        self.listening_address.clone()
    }
}
