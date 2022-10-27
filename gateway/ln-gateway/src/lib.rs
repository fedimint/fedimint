pub mod actor;
pub mod cln;
pub mod config;
pub mod ln;
pub mod rpc;
pub mod webserver;

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::{
    io::Cursor,
    sync::Arc,
    time::{Duration, Instant},
};

use actor::GatewayActor;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::{Address, Transaction};
use bitcoin_hashes::sha256;
use cln::HtlcAccepted;
use config::GatewayConfig;
use fedimint_api::{Amount, OutPoint, TransactionId};
use fedimint_server::modules::ln::contracts::{ContractId, Preimage};
use fedimint_server::modules::wallet::txoproof::TxOutProof;
use futures::Future;
use mint_client::{
    ln::PayInvoicePayload, mint::MintClientError, ClientError, FederationId, GatewayClient,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, warn};
use webserver::run_webserver;

use crate::ln::{LightningError, LnRpc};

pub type Result<T> = std::result::Result<T, LnGatewayError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiveInvoicePayload {
    // NOTE: On ReceiveInvoice, we extract the relevant federation id from the accepted htlc
    pub htlc_accepted: HtlcAccepted,
}

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

#[derive(Debug)]
pub enum GatewayRequest {
    ReceiveInvoice(GatewayRequestInner<ReceiveInvoicePayload>),
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
impl_gateway_request_trait!(
    ReceiveInvoicePayload,
    Preimage,
    GatewayRequest::ReceiveInvoice
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
    actors: HashMap<FederationId, Arc<GatewayActor>>,
    federation_client: Arc<GatewayClient>,
    ln_client: Arc<dyn LnRpc>,
    webserver: tokio::task::JoinHandle<axum::response::Result<()>>,
    receiver: mpsc::Receiver<GatewayRequest>,
}

impl LnGateway {
    pub fn new(
        cfg: GatewayConfig,
        federation_client: Arc<GatewayClient>,
        ln_client: Arc<dyn LnRpc>,
        sender: mpsc::Sender<GatewayRequest>,
        receiver: mpsc::Receiver<GatewayRequest>,
        bind_addr: SocketAddr,
    ) -> Self {
        // Run webserver asynchronously in tokio
        let webserver = tokio::spawn(run_webserver(cfg.password, bind_addr, sender));

        Self {
            actors: HashMap::new(),
            federation_client,
            ln_client,
            webserver,
            receiver,
        }
    }

    /// Register a federation to the gateway.
    ///
    /// # Returns
    ///
    /// A `GatewayActor` that can be used to execute gateway functions for the federation
    pub async fn register_federation(
        &mut self,
        client: Arc<GatewayClient>,
    ) -> Result<Arc<GatewayActor>> {
        let actor = Arc::new(
            GatewayActor::new(client.clone())
                .await
                .expect("Failed to create actor"),
        );

        let federation_id = FederationId(client.config().client_config.federation_name);
        self.actors.insert(federation_id, actor.clone());
        Ok(actor)
    }

    fn select_actor(&self, federation_id: FederationId) -> Result<Arc<GatewayActor>> {
        self.actors
            .get(&federation_id)
            .cloned()
            .ok_or(LnGatewayError::UnknownFederation)
    }

    pub async fn buy_preimage_offer(
        &self,
        payment_hash: &sha256::Hash,
        amount: &Amount,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(OutPoint, ContractId)> {
        let (outpoint, contract_id) = self
            .federation_client
            .buy_preimage_offer(payment_hash, amount, rng)
            .await?;
        Ok((outpoint, contract_id))
    }

    pub async fn await_preimage_decryption(&self, outpoint: OutPoint) -> Result<Preimage> {
        let preimage = self
            .federation_client
            .await_preimage_decryption(outpoint)
            .await?;
        Ok(preimage)
    }

    async fn buy_preimage_internal(
        &self,
        payment_hash: &sha256::Hash,
        invoice_amount: &Amount,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<Preimage> {
        let (out_point, contract_id) = self
            .federation_client
            .buy_preimage_offer(payment_hash, invoice_amount, &mut rng)
            .await?;

        debug!("Awaiting decryption of preimage of hash {}", payment_hash);
        match self
            .federation_client
            .await_preimage_decryption(out_point)
            .await
        {
            Ok(preimage) => {
                debug!("Decrypted preimage {:?}", preimage);
                Ok(preimage)
            }
            Err(e) => {
                warn!("Failed to decrypt preimage. Now requesting a refund: {}", e);
                self.federation_client
                    .refund_incoming_contract(contract_id, rng)
                    .await?;
                Err(LnGatewayError::ClientError(e))
            }
        }
    }

    pub async fn await_outgoing_contract_claimed(
        &self,
        contract_id: ContractId,
        outpoint: OutPoint,
    ) -> Result<()> {
        Ok(self
            .federation_client
            .await_outgoing_contract_claimed(contract_id, outpoint)
            .await?)
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

    async fn handle_htlc_incoming_msg(&self, htlc_accepted: HtlcAccepted) -> Result<Preimage> {
        let invoice_amount = htlc_accepted.htlc.amount;
        let payment_hash = htlc_accepted.htlc.payment_hash;
        let mut rng = rand::rngs::OsRng;

        debug!("Incoming htlc for payment hash {}", payment_hash);
        self.buy_preimage_internal(&payment_hash, &invoice_amount, &mut rng)
            .await
    }

    async fn handle_balance_msg(&self) -> Result<Amount> {
        let fetch_results = self.federation_client.fetch_all_coins().await;
        fetch_results
            .into_iter()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(self.federation_client.coins().total_amount())
    }
    async fn handle_address_msg(&self) -> Result<Address> {
        let mut rng = rand::rngs::OsRng;
        Ok(self.federation_client.get_new_pegin_address(&mut rng))
    }

    async fn handle_deposit_msg(&self, deposit: DepositPayload) -> Result<TransactionId> {
        let rng = rand::rngs::OsRng;
        self.federation_client
            .peg_in(deposit.txout_proof, deposit.transaction, rng)
            .await
            .map_err(LnGatewayError::ClientError)
    }

    async fn handle_withdraw_msg(&self, withdraw: WithdrawPayload) -> Result<TransactionId> {
        let rng = rand::rngs::OsRng;
        let peg_out = self
            .federation_client
            .new_peg_out_with_fees(withdraw.amount, withdraw.address)
            .await
            .unwrap();
        self.federation_client
            .peg_out(peg_out, rng)
            .await
            .map_err(LnGatewayError::ClientError)
            .map(|out_point| out_point.txid)
    }

    pub async fn run(&mut self) -> Result<()> {
        // Regster gateway with federation
        // FIXME: This call is critically dependent on the federation being up and running.
        // We should either use a retry strategy, OR register federations on the gateway at runtime
        // as proposed in https://github.com/fedimint/fedimint/issues/699
        self.federation_client
            .register_with_federation(self.federation_client.config().into())
            .await
            .expect("Failed to register with federation");

        // TODO: try to drive forward outgoing and incoming payments that were interrupted
        loop {
            let least_wait_until = Instant::now() + Duration::from_millis(100);
            for fetch_result in self.federation_client.fetch_all_coins().await {
                if let Err(e) = fetch_result {
                    debug!(error = %e, "Fetching coins failed")
                };
            }

            // Handle messages from webserver and plugin
            while let Ok(msg) = self.receiver.try_recv() {
                tracing::trace!("Gateway received message {:?}", msg);
                match msg {
                    GatewayRequest::ReceiveInvoice(inner) => {
                        inner
                            .handle(|inner| self.handle_htlc_incoming_msg(inner.htlc_accepted))
                            .await;
                    }
                    GatewayRequest::PayInvoice(inner) => {
                        inner
                            .handle(|payload| self.handle_pay_invoice_msg(payload))
                            .await;
                    }
                    GatewayRequest::Balance(inner) => {
                        inner.handle(|_| self.handle_balance_msg()).await;
                    }
                    GatewayRequest::DepositAddress(inner) => {
                        inner.handle(|_| self.handle_address_msg()).await;
                    }
                    GatewayRequest::Deposit(inner) => {
                        inner
                            .handle(|deposit| self.handle_deposit_msg(deposit))
                            .await;
                    }
                    GatewayRequest::Withdraw(inner) => {
                        inner
                            .handle(|withdraw| self.handle_withdraw_msg(withdraw))
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
