pub mod cln;
pub mod ln;
pub mod messaging;
pub mod webserver;

use std::{
    borrow::Cow,
    io::Cursor,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::{Address, Transaction};
use bitcoin_hashes::sha256;
use cln::HtlcAccepted;
use fedimint_api::{Amount, OutPoint, TransactionId};
use fedimint_server::{
    modules::ln::contracts::{ContractId, Preimage},
    modules::wallet::txoproof::TxOutProof,
};
use futures::Future;
use mint_client::GatewayClient;
use mint_client::PaymentParameters;
use mint_client::{mint::MintClientError, Client, ClientError, GatewayClientConfig};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer};
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot, Mutex},
    task::JoinHandle,
};
use tracing::{debug, instrument, warn};

use crate::{
    ln::{GatewayLnRpcConfig, GatewayLnRpcConfigError, LightningError, LnRpc},
    messaging::{GatewayMessageChannel, GatewayMessageReceiver},
    webserver::run_webserver,
};

pub type Result<T> = std::result::Result<T, LnGatewayError>;

#[derive(Debug)]
pub struct BalancePayload;

#[derive(Debug)]
pub struct DepositAddressPayload;

#[derive(Debug, Deserialize)]
pub struct DepositPayload(
    TxOutProof,
    #[serde(deserialize_with = "serde_hex_deserialize")] Transaction,
);

#[derive(Debug, Deserialize)]
pub struct WithdrawPayload(
    Address,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")] bitcoin::Amount,
);

#[derive(Debug)]
pub enum GatewayRequest {
    HtlcAccepted(GatewayRequestInner<HtlcAccepted>),
    PayInvoice(GatewayRequestInner<ContractId>),
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
impl_gateway_request_trait!(HtlcAccepted, Preimage, GatewayRequest::HtlcAccepted);
impl_gateway_request_trait!(ContractId, (), GatewayRequest::PayInvoice);
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

pub struct GatewayActor {
    federation_client: Arc<GatewayClient>,
    ln_rpc: Arc<dyn LnRpc>,
    receiver: Arc<Mutex<mpsc::Receiver<GatewayRequest>>>,
}

impl GatewayActor {
    pub fn new(
        receiver: mpsc::Receiver<GatewayRequest>,
        federation_client: Arc<GatewayClient>,
        ln_rpc: Arc<dyn LnRpc>,
    ) -> Self {
        // TODO: support ln_rpc swaps in-flight, after instantiation
        Self {
            receiver: Arc::new(Mutex::new(receiver)),
            federation_client,
            ln_rpc,
        }
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

    #[instrument(skip_all, fields(%contract_id))]
    pub async fn pay_invoice(
        &self,
        contract_id: ContractId,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<OutPoint> {
        debug!("Fetching contract");
        let contract_account = self
            .federation_client
            .fetch_outgoing_contract(contract_id)
            .await?;

        let payment_params = self
            .federation_client
            .validate_outgoing_account(&contract_account)
            .await?;

        debug!(
            account = ?contract_account,
            "Fetched and validated contract account"
        );

        self.federation_client
            .save_outgoing_payment(contract_account.clone());

        let is_internal_payment = payment_params.maybe_internal
            && self
                .federation_client
                .ln_client()
                .offer_exists(payment_params.payment_hash)
                .await
                .unwrap_or(false);

        let preimage_res = if is_internal_payment {
            self.buy_preimage_internal(
                &payment_params.payment_hash,
                &payment_params.invoice_amount,
                &mut rng,
            )
            .await
        } else {
            self.buy_preimage_external(&contract_account.contract.invoice, &payment_params)
                .await
        };

        match preimage_res {
            Ok(preimage) => {
                let outpoint = self
                    .federation_client
                    .claim_outgoing_contract(contract_id, preimage, rng)
                    .await?;

                Ok(outpoint)
            }
            Err(e) => {
                warn!("Invoice payment failed: {}. Aborting", e);
                // FIXME: combine both errors?
                self.federation_client
                    .abort_outgoing_payment(contract_id)
                    .await?;
                Err(e)
            }
        }
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

    async fn buy_preimage_external(
        &self,
        invoice: &str,
        payment_params: &PaymentParameters,
    ) -> Result<Preimage> {
        match self
            .ln_rpc
            .pay(
                invoice,
                payment_params.max_delay,
                payment_params.max_fee_percent(),
            )
            .await
        {
            Ok(preimage) => {
                debug!(?preimage, "Successfully paid LN invoice");
                Ok(preimage)
            }
            Err(e) => {
                warn!("LN payment failed, aborting");
                Err(LnGatewayError::CouldNotRoute(e))
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

    async fn handle_pay_invoice_msg(&self, contract_id: ContractId) -> Result<()> {
        let rng = rand::rngs::OsRng;
        let outpoint = self.pay_invoice(contract_id, rng).await?;
        self.await_outgoing_contract_claimed(contract_id, outpoint)
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
            .peg_in(deposit.0, deposit.1, rng)
            .await
            .map_err(LnGatewayError::ClientError)
    }

    async fn handle_withdraw_msg(&self, withdraw: WithdrawPayload) -> Result<TransactionId> {
        let rng = rand::rngs::OsRng;
        let peg_out = self
            .federation_client
            .new_peg_out_with_fees(withdraw.1, withdraw.0)
            .await
            .unwrap();
        self.federation_client
            .peg_out(peg_out, rng)
            .await
            .map_err(LnGatewayError::ClientError)
            .map(|out_point| out_point.txid)
    }
}

#[async_trait]
impl GatewayMessageReceiver for GatewayActor {
    async fn receive(&self) {
        for fetch_result in self.federation_client.fetch_all_coins().await {
            if let Err(e) = fetch_result {
                debug!(error = %e, "Fetching coins failed")
            };
        }

        // Handle messages from webserver and plugin
        while let Ok(msg) = self.receiver.lock().await.try_recv() {
            tracing::trace!("Gateway received message {:?}", msg);
            match msg {
                GatewayRequest::HtlcAccepted(inner) => {
                    inner
                        .handle(|htlc_accepted| self.handle_htlc_incoming_msg(htlc_accepted))
                        .await;
                }
                GatewayRequest::PayInvoice(inner) => {
                    inner
                        .handle(|contract_id| self.handle_pay_invoice_msg(contract_id))
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
    }
}

#[derive(Default)]
pub struct LnGateway {
    ln_rpc: Option<Arc<dyn LnRpc>>,
    actors: Vec<Arc<GatewayActor>>,
    webserver: Option<JoinHandle<axum::response::Result<()>>>,
    // TODO: Impl a gateway 'Message Router' thatwe can reference instead of a direct receiver
    receiver: Option<mpsc::Receiver<GatewayRequest>>,
}

impl LnGateway {
    pub fn new() -> Self {
        Self {
            actors: Vec::new(),
            ln_rpc: None,
            webserver: None,
            receiver: None,
        }
    }

    /// Register a lew lightning RPC on the gateway.
    /// If there was an existing RPC, a successful registration of a new ln rpc will replace the old one.
    pub async fn register_ln_rpc(
        &mut self,
        gateway_ln_rpc_config: Arc<Mutex<GatewayLnRpcConfig>>,
    ) -> Result<&mut Self> {
        let (sender, receiver): (mpsc::Sender<GatewayRequest>, mpsc::Receiver<GatewayRequest>) =
            mpsc::channel(100);

        let ln_rpc_messenger = GatewayMessageChannel::new(&sender);

        // Register the lightning RPC client
        match gateway_ln_rpc_config
            .lock()
            .await
            .init(ln_rpc_messenger)
            .await
        {
            Ok(config) => {
                self.ln_rpc = Some(Arc::clone(&config.ln_rpc));

                // TODO: figure out how to bind a single gateway webserver to any [+ multiple?] ln rpcs
                // Run a webserver on the rpc bind address
                let webserver_messenger = GatewayMessageChannel::new(&sender);
                let webserver = tokio::spawn(async move {
                    run_webserver(webserver_messenger, &config.bind_addr).await
                });
                self.webserver = Some(webserver);
            }
            Err(e) => {
                return Err(LnGatewayError::LnRpcConfigE(e));
            }
        }

        // Temp: We keep a reference to the receiver so we can later istantiate an actor on demand
        self.receiver = Some(receiver); // TODO: instantiate a 'MessageRouter' with the receiver

        Ok(self)
    }

    /// Register a federation to the gateway.
    ///
    /// # Returns
    ///
    /// A `GatewayActor` that can be used to execute gateway functions for the federation
    pub async fn register_federation(
        &mut self,
        client: Arc<Client<GatewayClientConfig>>,
    ) -> Result<Arc<GatewayActor>> {
        // TODO: Support creation multiple actors and thus multiple federations.
        // for now, we take the receiver when registering the very first federation
        let receiver = self.receiver.take().expect("No receiver declared");

        let ln_rpc = self
            .ln_rpc
            .clone()
            .ok_or_else(|| LnGatewayError::Other(anyhow::anyhow!("No ln rpc registered")))?;

        // Register the provided client with a federation.
        // This assumes the client provider did not register the client already.
        client
            .register_with_federation(client.config().into())
            .await
            .expect("Failed to register client with federation");

        let actor = Arc::new(GatewayActor::new(receiver, client, ln_rpc));
        self.actors.push(actor.clone());

        Ok(actor)
    }

    pub async fn run(self) -> Result<()> {
        // TODO: try to drive forward outgoing and incoming payments that were interrupted
        // TODO: try run gateway rpc actors concurrently
        loop {
            let least_wait_until = Instant::now() + Duration::from_millis(100);

            // Handle messages from webserver and plugin
            for actor in &self.actors {
                actor.receive().await;
            }

            fedimint_api::task::sleep_until(least_wait_until).await;
        }
    }
}

impl Drop for LnGateway {
    fn drop(&mut self) {
        if let Some(mut webserver) = self.webserver.take() {
            webserver.abort();
            let _ = futures::executor::block_on(&mut webserver);
        }
    }
}

#[derive(Debug, Error)]
pub enum LnGatewayError {
    #[error("instantiation error")]
    InstantiationError,
    #[error("Federation client operation error: {0:?}")]
    ClientError(#[from] ClientError),
    #[error("Our LN node could not route the payment: {0:?}")]
    CouldNotRoute(LightningError),
    #[error("Mint client error: {0:?}")]
    MintClientE(#[from] MintClientError),
    #[error("Mint error: {0:?}")]
    LnRpcConfigE(#[from] GatewayLnRpcConfigError),
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

impl IntoResponse for LnGatewayError {
    fn into_response(self) -> Response {
        let mut err = Cow::<'static, str>::Owned(format!("{:?}", self)).into_response();
        *err.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        err
    }
}
