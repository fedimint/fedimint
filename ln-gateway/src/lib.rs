pub mod cln;
pub mod ln;
pub mod webserver;

use crate::ln::{LightningError, LnRpc};
use bitcoin_hashes::sha256::Hash;
use cln::HtlcAccepted;
use minimint::modules::ln::contracts::{incoming::Preimage, ContractId};
use minimint_api::{Amount, OutPoint};
use mint_client::clients::gateway::{GatewayClient, GatewayClientError};
use rand::{CryptoRng, RngCore};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, instrument, warn};
use webserver::run_webserver;

#[derive(Debug)]
pub enum GatewayRequest {
    HtlcAccepted(
        HtlcAccepted,
        oneshot::Sender<Result<Preimage, LnGatewayError>>,
    ),
    PayInvoice(ContractId, oneshot::Sender<Result<(), LnGatewayError>>),
}

pub struct LnGateway {
    federation_client: Arc<GatewayClient>,
    ln_client: Arc<dyn LnRpc>,
    webserver: tokio::task::JoinHandle<tide::Result<()>>,
    receiver: mpsc::Receiver<GatewayRequest>,
}

impl LnGateway {
    pub fn new(
        federation_client: Arc<GatewayClient>,
        ln_client: Box<dyn LnRpc>,
        sender: mpsc::Sender<GatewayRequest>,
        receiver: mpsc::Receiver<GatewayRequest>,
    ) -> Self {
        let ln_client: Arc<dyn LnRpc> = ln_client.into();
        let webserver = tokio::spawn(run_webserver(sender));
        LnGateway {
            federation_client,
            ln_client,
            webserver,
            receiver,
        }
    }

    pub async fn buy_preimage_offer(
        &self,
        payment_hash: &Hash,
        amount: &Amount,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(OutPoint, ContractId), LnGatewayError> {
        let (outpoint, contract_id) = self
            .federation_client
            .buy_preimage_offer(payment_hash, amount, rng)
            .await?;
        Ok((outpoint, contract_id))
    }

    pub async fn await_preimage_decryption(
        &self,
        outpoint: OutPoint,
    ) -> Result<Preimage, LnGatewayError> {
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
        rng: impl RngCore + CryptoRng,
    ) -> Result<OutPoint, LnGatewayError> {
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

        let preimage = match self
            .ln_client
            .pay(
                &contract_account.contract.invoice,
                payment_params.max_delay,
                payment_params.max_fee_percent,
            )
            .await
        {
            Ok(preimage) => {
                debug!(?preimage, "Successfully paid LN invoice");
                preimage
            }
            Err(e) => {
                warn!("LN payment failed, aborting");
                self.federation_client.abort_outgoing_payment(contract_id);
                return Err(LnGatewayError::CouldNotRoute(e));
            }
        };

        // FIXME: figure out how to treat RNGs (maybe include in context?)
        debug!("Claiming outgoing contract");
        let outpoint = self
            .federation_client
            .claim_outgoing_contract(contract_id, preimage, rng)
            .await?;

        Ok(outpoint)
    }

    pub async fn await_outgoing_contract_claimed(
        &self,
        contract_id: ContractId,
        outpoint: OutPoint,
    ) -> Result<(), LnGatewayError> {
        Ok(self
            .federation_client
            .await_outgoing_contract_claimed(contract_id, outpoint)
            .await?)
    }

    async fn handle_pay_invoice_msg(&self, contract_id: ContractId) -> Result<(), LnGatewayError> {
        let rng = rand::rngs::OsRng::new().unwrap();
        let outpoint = self.pay_invoice(contract_id, rng).await?;
        self.await_outgoing_contract_claimed(contract_id, outpoint)
            .await?;
        Ok(())
    }

    async fn handle_htlc_incoming_msg(
        &self,
        htlc_accepted: HtlcAccepted,
    ) -> Result<Preimage, LnGatewayError> {
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

    pub async fn run(&mut self) -> Result<(), LnGatewayError> {
        // TODO: try to drive forward outgoing and incoming payments that were interrupted
        loop {
            let least_wait_until = Instant::now() + Duration::from_millis(100);
            let pending_fetches = self
                .federation_client
                .list_fetchable_coins()
                .into_iter()
                .map(|out_point| {
                    // TODO: get rid of cloning
                    let federation_client = self.federation_client.clone();
                    async move {
                        if let Err(e) = federation_client.fetch_coins(out_point).await {
                            debug!(error = %e, "Fetching coins failed");
                        }
                    }
                })
                .collect::<Vec<_>>();
            futures::future::join_all(pending_fetches).await;

            // Handle messages from webserver and plugin
            while let Ok(msg) = self.receiver.try_recv() {
                tracing::trace!("Gateway received message {:?}", msg);
                match msg {
                    GatewayRequest::HtlcAccepted(htlc_accepted, sender) => {
                        let result = self.handle_htlc_incoming_msg(htlc_accepted).await;
                        sender.send(result).expect("couldn't send over channel");
                    }
                    GatewayRequest::PayInvoice(contract_id, sender) => {
                        let result = self.handle_pay_invoice_msg(contract_id).await;
                        sender.send(result).expect("couldn't send over channel");
                    }
                }
            }

            minimint_api::task::sleep_until(least_wait_until).await;
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
    #[error("Federation operation error: {0:?}")]
    FederationError(#[from] GatewayClientError),
    #[error("Our LN node could not route the payment: {0:?}")]
    CouldNotRoute(LightningError),
}
