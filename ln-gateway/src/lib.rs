pub mod cln;
pub mod ln;
mod util;
pub mod webserver;

use crate::ln::{LightningError, LnRpc};
use crate::util::{ThenAsync, UnwrapOrElseAsync};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::{Address, Transaction};
use bitcoin_hashes::sha256;
use cln::HtlcAccepted;
use fedimint::modules::ln::contracts::{incoming::Preimage, ContractId};
use fedimint::modules::wallet::txoproof::TxOutProof;
use fedimint_api::{Amount, OutPoint, TransactionId};
use futures::Future;
use mint_client::mint::MintClientError;
use mint_client::{ClientError, GatewayClient, PaymentParameters};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::{
    io::Cursor,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, instrument, warn};
use webserver::run_webserver;

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
        self.sender
            .send(result)
            .expect("couldn't send over channel");
    }
}

pub struct LnGateway {
    federation_client: Arc<GatewayClient>,
    ln_client: Arc<dyn LnRpc>,
    webserver: tokio::task::JoinHandle<axum::response::Result<()>>,
    receiver: mpsc::Receiver<GatewayRequest>,
}

impl LnGateway {
    pub fn new(
        federation_client: Arc<GatewayClient>,
        ln_client: Arc<dyn LnRpc>,
        sender: mpsc::Sender<GatewayRequest>,
        receiver: mpsc::Receiver<GatewayRequest>,
        bind_addr: SocketAddr,
    ) -> Self {
        // let ln_client: Arc<dyn LnRpc> = ln_client.into();

        // Run webserver asynchronously in tokio
        let webserver = tokio::spawn(run_webserver(bind_addr, sender));

        Self {
            federation_client,
            ln_client,
            webserver,
            receiver,
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

        // If this could be an internal payment try to buy the preimage directly. Otherwise or if
        // this fails try to route the payment via our attached LN node.
        let preimage_res = payment_params
            .maybe_internal
            .then_async(async {
                self.buy_preimage_internal(&payment_params, &mut rng)
                    .await
                    .ok()
            })
            .await
            .flatten()
            .map(Result::Ok)
            .unwrap_or_else_async(
                self.buy_preimage_external(&contract_account.contract.invoice, &payment_params),
            )
            .await;

        match preimage_res {
            Ok(preimage) => {
                let outpoint = self
                    .federation_client
                    .claim_outgoing_contract(contract_id, preimage, rng)
                    .await?;

                Ok(outpoint)
            }
            Err(e) => {
                warn!("LN payment failed, aborting");
                self.federation_client.abort_outgoing_payment(contract_id);
                Err(e)
            }
        }
    }

    async fn buy_preimage_internal(
        &self,
        payment_params: &PaymentParameters,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<[u8; 32]> {
        let (out_point, _) = self
            .federation_client
            .buy_preimage_offer(
                &payment_params.payment_hash,
                &payment_params.invoice_amount,
                &mut rng,
            )
            .await?;
        let preimage = self
            .federation_client
            .await_preimage_decryption(out_point)
            .await?;
        Ok(preimage.0.serialize())
    }

    async fn buy_preimage_external(
        &self,
        invoice: &str,
        payment_params: &PaymentParameters,
    ) -> Result<[u8; 32]> {
        match self
            .ln_client
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
        let rng = rand::rngs::OsRng::new().unwrap();
        let outpoint = self.pay_invoice(contract_id, rng).await?;
        self.await_outgoing_contract_claimed(contract_id, outpoint)
            .await?;
        Ok(())
    }

    async fn handle_htlc_incoming_msg(&self, htlc_accepted: HtlcAccepted) -> Result<Preimage> {
        let amount = htlc_accepted.htlc.amount;
        let payment_hash = htlc_accepted.htlc.payment_hash;
        let rng = rand::rngs::OsRng::new().unwrap();

        tracing::debug!("Incoming htlc for payment hash {}", payment_hash);
        let (outpoint, _) = self.buy_preimage_offer(&payment_hash, &amount, rng).await?;
        tracing::debug!("Decrypting preimage {}", payment_hash);
        let preimage = self.await_preimage_decryption(outpoint).await?;
        tracing::debug!("Decrypted preimage {:?}", payment_hash);

        Ok(preimage)
    }

    async fn handle_balance_msg(&self) -> Result<Amount> {
        let fetch_results = self.federation_client.fetch_all_coins().await;
        fetch_results
            .into_iter()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(self.federation_client.coins().total_amount())
    }
    async fn handle_address_msg(&self) -> Result<Address> {
        let mut rng = rand::rngs::OsRng::new().unwrap();
        Ok(self.federation_client.get_new_pegin_address(&mut rng))
    }

    async fn handle_deposit_msg(&self, deposit: DepositPayload) -> Result<TransactionId> {
        let rng = rand::rngs::OsRng::new().unwrap();
        self.federation_client
            .peg_in(deposit.0, deposit.1, rng)
            .await
            .map_err(LnGatewayError::ClientError)
    }

    async fn handle_withdraw_msg(&self, withdraw: WithdrawPayload) -> Result<TransactionId> {
        let rng = rand::rngs::OsRng::new().unwrap();
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

    pub async fn run(&mut self) -> Result<()> {
        // Regster gateway with federation
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
}

pub fn serde_hex_deserialize<'d, T: bitcoin::consensus::Decodable, D: Deserializer<'d>>(
    d: D,
) -> std::result::Result<T, D::Error> {
    if d.is_human_readable() {
        let bytes = hex::decode::<String>(Deserialize::deserialize(d)?)
            .map_err(serde::de::Error::custom)?;
        T::consensus_decode(Cursor::new(&bytes))
            .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    } else {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        T::consensus_decode(Cursor::new(&bytes))
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
