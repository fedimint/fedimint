pub mod actor;
pub mod client;
pub mod cln;
pub mod config;
pub mod ln;
pub mod rpc;
pub mod utils;
pub mod webserver;

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::{
    io::Cursor,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::{Address, Transaction};
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_api::{Amount, NumPeers, TransactionId};
use fedimint_server::{
    config::ClientConfig,
    modules::{ln::contracts::Preimage, wallet::txoproof::TxOutProof},
};
use futures::Future;
use mint_client::{
    api::{WsFederationApi, WsFederationConnect},
    ln::PayInvoicePayload,
    mint::MintClientError,
    query::CurrentConsensus,
    ClientError, FederationId, GatewayClient, GatewayClientConfig,
};
use rand::thread_rng;
use secp256k1::{KeyPair, PublicKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, warn};
use url::Url;

use crate::{
    actor::GatewayActor,
    client::GatewayClientBuilder,
    cln::HtlcAccepted,
    config::GatewayConfig,
    ln::{LightningError, LnRpc},
    webserver::run_webserver,
};

pub type Result<T> = std::result::Result<T, LnGatewayError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFedPayload {
    pub connect: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceivePaymentPayload {
    // NOTE: On ReceivePayment signal from ln_rpc,
    // we extract the relevant federation id from the accepted htlc
    pub htlc_accepted: HtlcAccepted,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoPayload;

#[derive(Debug, Serialize, Deserialize)]
pub struct BalancePayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositAddressPayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositPayload {
    pub federation_id: FederationId,
    pub txout_proof: TxOutProof,
    #[serde(
        deserialize_with = "serde_hex_deserialize",
        serialize_with = "serde_hex_serialize"
    )]
    pub transaction: Transaction,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawPayload {
    pub federation_id: FederationId,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
    pub address: Address,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayInfo {
    pub version_hash: String,
    pub federations: Vec<FederationId>,
}

#[derive(Debug)]
pub enum GatewayRequest {
    Info(GatewayRequestInner<InfoPayload>),
    RegisterFederation(GatewayRequestInner<RegisterFedPayload>),
    ReceivePayment(GatewayRequestInner<ReceivePaymentPayload>),
    PayInvoice(GatewayRequestInner<PayInvoicePayload>),
    Balance(GatewayRequestInner<BalancePayload>),
    DepositAddress(GatewayRequestInner<DepositAddressPayload>),
    Deposit(GatewayRequestInner<DepositPayload>),
    Withdraw(GatewayRequestInner<WithdrawPayload>),
}

#[derive(Debug)]
pub struct GatewayRequestInner<R: GatewayRequestTrait> {
    request: R,
    sender: oneshot::Sender<Result<R::Response>>,
}

pub trait GatewayRequestTrait {
    type Response;

    fn to_enum(self, sender: oneshot::Sender<Result<Self::Response>>) -> GatewayRequest;
}

macro_rules! impl_gateway_request_trait {
    ($req:ty, $res:ty, $variant:expr) => {
        impl GatewayRequestTrait for $req {
            type Response = $res;
            fn to_enum(self, sender: oneshot::Sender<Result<Self::Response>>) -> GatewayRequest {
                $variant(GatewayRequestInner {
                    request: self,
                    sender,
                })
            }
        }
    };
}

impl_gateway_request_trait!(InfoPayload, GatewayInfo, GatewayRequest::Info);
impl_gateway_request_trait!(RegisterFedPayload, (), GatewayRequest::RegisterFederation);
impl_gateway_request_trait!(
    ReceivePaymentPayload,
    Preimage,
    GatewayRequest::ReceivePayment
);
impl_gateway_request_trait!(PayInvoicePayload, (), GatewayRequest::PayInvoice);
impl_gateway_request_trait!(BalancePayload, Amount, GatewayRequest::Balance);
impl_gateway_request_trait!(
    DepositAddressPayload,
    Address,
    GatewayRequest::DepositAddress
);
impl_gateway_request_trait!(DepositPayload, TransactionId, GatewayRequest::Deposit);
impl_gateway_request_trait!(WithdrawPayload, TransactionId, GatewayRequest::Withdraw);

impl<T> GatewayRequestInner<T>
where
    T: GatewayRequestTrait,
    T::Response: std::fmt::Debug,
{
    async fn handle<F: Fn(T) -> FF, FF: Future<Output = Result<T::Response>>>(self, handler: F) {
        let result = handler(self.request).await;
        if self.sender.send(result).is_err() {
            // TODO: figure out how to log the result
            tracing::error!("Plugin hung up");
        }
    }
}

pub struct LnGateway {
    config: GatewayConfig,
    actors: Mutex<HashMap<Sha256Hash, Arc<GatewayActor>>>,
    ln_client: Arc<dyn LnRpc>,
    webserver: tokio::task::JoinHandle<axum::response::Result<()>>,
    receiver: mpsc::Receiver<GatewayRequest>,
    client_builder: GatewayClientBuilder,
    // TODO: consider wrapping bind_addr, and node_pubkey in GatewayConfig
    bind_addr: SocketAddr,
    pub_key: PublicKey,
}

impl LnGateway {
    pub fn new(
        config: GatewayConfig,
        ln_client: Arc<dyn LnRpc>,
        client_builder: GatewayClientBuilder,
        // TODO: consider encapsulating message channel within LnGateway
        sender: mpsc::Sender<GatewayRequest>,
        receiver: mpsc::Receiver<GatewayRequest>,
        // TODO: consider wrapping bind_addr, and node_pubkey in GatewayConfig
        bind_addr: SocketAddr,
        pub_key: PublicKey,
    ) -> Self {
        // Run webserver asynchronously in tokio
        let webserver = tokio::spawn(run_webserver(config.password.clone(), bind_addr, sender));

        Self {
            config,
            actors: Mutex::new(HashMap::new()),
            ln_client,
            webserver,
            receiver,
            client_builder,
            bind_addr,
            pub_key,
        }
    }

    fn select_actor(&self, federation_id: FederationId) -> Result<Arc<GatewayActor>> {
        self.actors
            .lock()
            .map_err(|_| LnGatewayError::Other(anyhow::anyhow!("Failed to select an actor")))?
            .get(&federation_id.hash())
            .cloned()
            .ok_or(LnGatewayError::UnknownFederation)
    }

    /// Register a federation to the gateway.
    ///
    /// # Returns
    ///
    /// A `GatewayActor` that can be used to execute gateway functions for the federation
    pub async fn register_federation(
        &self,
        client: Arc<GatewayClient>,
    ) -> Result<Arc<GatewayActor>> {
        let federation_id = FederationId(client.config().client_config.federation_name);

        let actor = Arc::new(
            GatewayActor::new(client.clone(), federation_id.clone())
                .await
                .expect("Failed to create actor"),
        );

        if let Ok(mut actors) = self.actors.lock() {
            actors.insert(federation_id.hash(), actor.clone());
        }
        Ok(actor)
    }

    // Webserver handler for requests to register a federation
    async fn handle_register_federation(&self, payload: RegisterFedPayload) -> Result<()> {
        let connect: WsFederationConnect =
            serde_json::from_str(&payload.connect).expect("Invalid federation connect info");
        let api = WsFederationApi::new(connect.members);

        let client_cfg: ClientConfig = api
            .request(
                "/config",
                (),
                CurrentConsensus::new(api.peers().one_honest()),
            )
            .await
            .expect("Failed to get client config");

        let mut rng = thread_rng();
        let ctx = secp256k1::Secp256k1::new();
        let kp_fed = KeyPair::new(&ctx, &mut rng);

        let gw_client_cfg = GatewayClientConfig {
            client_config: client_cfg,
            redeem_key: kp_fed,
            timelock_delta: 10,
            node_pub_key: self.pub_key,
            api: Url::parse(format!("http://{}", self.bind_addr).as_str())
                .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
        };

        let client = self.client_builder.build(gw_client_cfg.clone())?;

        if let Err(e) = self.register_federation(Arc::new(client)).await {
            error!("Failed to register federation: {}", e);
        }

        if let Err(e) = self.client_builder.save_config(gw_client_cfg) {
            warn!(
                "Failed to save default federation client configuration: {}",
                e
            );
        }

        Ok(())
    }

    async fn handle_get_info(&self, _payload: InfoPayload) -> Result<GatewayInfo> {
        if let Ok(actors) = self.actors.lock() {
            return Ok(GatewayInfo {
                version_hash: env!("GIT_HASH").to_string(),
                federations: actors.iter().map(|(_, actor)| actor.id.clone()).collect(),
            });
        }
        Err(LnGatewayError::Other(anyhow::anyhow!(
            "Failed to fetch gateway get info"
        )))
    }

    async fn handle_receive_invoice_msg(&self, payload: ReceivePaymentPayload) -> Result<Preimage> {
        let ReceivePaymentPayload { htlc_accepted } = payload;

        let invoice_amount = htlc_accepted.htlc.amount;
        let payment_hash = htlc_accepted.htlc.payment_hash;
        debug!("Incoming htlc for payment hash {}", payment_hash);

        // FIXME: Issue 664: We should avoid having a special reference to a federation
        // all requests, including `ReceivePaymentPayload`, should contain the federation id
        // TODO: Parse federation id from routing hint in htlc_accepted message
        self.select_actor(self.config.default_federation.clone())?
            .buy_preimage_internal(&payment_hash, &invoice_amount)
            .await
    }

    async fn handle_pay_invoice_msg(&self, payload: PayInvoicePayload) -> Result<()> {
        let PayInvoicePayload {
            federation_id,
            contract_id,
        } = payload;

        let actor = self.select_actor(federation_id)?;
        let outpoint = actor
            .pay_invoice(self.ln_client.clone(), contract_id)
            .await?;
        actor
            .await_outgoing_contract_claimed(contract_id, outpoint)
            .await?;
        Ok(())
    }

    async fn handle_balance_msg(&self, payload: BalancePayload) -> Result<Amount> {
        self.select_actor(payload.federation_id)?
            .get_balance()
            .await
    }

    async fn handle_address_msg(&self, payload: DepositAddressPayload) -> Result<Address> {
        self.select_actor(payload.federation_id)?
            .get_deposit_address()
    }

    async fn handle_deposit_msg(&self, payload: DepositPayload) -> Result<TransactionId> {
        let DepositPayload {
            txout_proof,
            transaction,
            federation_id,
        } = payload;

        self.select_actor(federation_id)?
            .deposit(txout_proof, transaction)
            .await
    }

    async fn handle_withdraw_msg(&self, payload: WithdrawPayload) -> Result<TransactionId> {
        let WithdrawPayload {
            amount,
            address,
            federation_id,
        } = payload;

        self.select_actor(federation_id)?
            .withdraw(amount, address)
            .await
    }

    pub async fn run(&mut self) -> Result<()> {
        // TODO: try to drive forward outgoing and incoming payments that were interrupted
        loop {
            let least_wait_until = Instant::now() + Duration::from_millis(100);

            // Sync wallet for the default federation
            // TODO: We should sync wallets for all the federation clients
            self.select_actor(self.config.default_federation.clone())?
                .fetch_all_coins()
                .await;

            // Handle messages from webserver and plugin
            while let Ok(msg) = self.receiver.try_recv() {
                tracing::trace!("Gateway received message {:?}", msg);
                match msg {
                    GatewayRequest::Info(inner) => {
                        inner.handle(|payload| self.handle_get_info(payload)).await;
                    }
                    GatewayRequest::RegisterFederation(inner) => {
                        inner
                            .handle(|payload| self.handle_register_federation(payload))
                            .await;
                    }
                    GatewayRequest::ReceivePayment(inner) => {
                        inner
                            .handle(|payload| self.handle_receive_invoice_msg(payload))
                            .await;
                    }
                    GatewayRequest::PayInvoice(inner) => {
                        inner
                            .handle(|payload| self.handle_pay_invoice_msg(payload))
                            .await;
                    }
                    GatewayRequest::Balance(inner) => {
                        inner
                            .handle(|payload| self.handle_balance_msg(payload))
                            .await;
                    }
                    GatewayRequest::DepositAddress(inner) => {
                        inner
                            .handle(|payload| self.handle_address_msg(payload))
                            .await;
                    }
                    GatewayRequest::Deposit(inner) => {
                        inner
                            .handle(|payload| self.handle_deposit_msg(payload))
                            .await;
                    }
                    GatewayRequest::Withdraw(inner) => {
                        inner
                            .handle(|payload| self.handle_withdraw_msg(payload))
                            .await;
                    }
                }
            }

            fedimint_api::task::sleep_until(least_wait_until).await;
        }
    }
}

impl Drop for LnGateway {
    fn drop(&mut self) {
        self.webserver.abort();
        let _ = futures::executor::block_on(&mut self.webserver);
    }
}

#[derive(Debug, Error)]
pub enum LnGatewayError {
    #[error("Federation client operation error: {0:?}")]
    ClientError(#[from] ClientError),
    #[error("Our LN node could not route the payment: {0:?}")]
    CouldNotRoute(LightningError),
    #[error("Mint client error: {0:?}")]
    MintClientE(#[from] MintClientError),
    #[error("Actor not found")]
    UnknownFederation,
    #[error("Other: {0:?}")]
    Other(#[from] anyhow::Error),
}

pub fn serde_hex_deserialize<'d, T: bitcoin::consensus::Decodable, D: Deserializer<'d>>(
    d: D,
) -> std::result::Result<T, D::Error> {
    if d.is_human_readable() {
        let bytes = hex::decode::<String>(Deserialize::deserialize(d)?)
            .map_err(serde::de::Error::custom)?;
        T::consensus_decode(&mut Cursor::new(&bytes))
            .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    } else {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        T::consensus_decode(&mut Cursor::new(&bytes))
            .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

pub fn serde_hex_serialize<T: bitcoin::consensus::Encodable, S: Serializer>(
    t: &T,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    let mut bytes = vec![];
    T::consensus_encode(t, &mut bytes).map_err(serde::ser::Error::custom)?;

    if s.is_human_readable() {
        s.serialize_str(&hex::encode(bytes))
    } else {
        s.serialize_bytes(&bytes)
    }
}

impl IntoResponse for LnGatewayError {
    fn into_response(self) -> Response {
        let mut err = Cow::<'static, str>::Owned(format!("{:?}", self)).into_response();
        *err.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        err
    }
}
