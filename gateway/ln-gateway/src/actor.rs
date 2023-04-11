use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Address, Transaction};
use bitcoin_hashes::{sha256, Hash};
use fedimint_client_legacy::modules::ln::contracts::{ContractId, Preimage};
use fedimint_client_legacy::modules::ln::route_hints::RouteHint;
use fedimint_client_legacy::modules::wallet::txoproof::TxOutProof;
use fedimint_client_legacy::{GatewayClient, PaymentParameters};
use fedimint_core::task::{RwLock, TaskGroup};
use fedimint_core::{Amount, OutPoint, TransactionId};
use futures::stream::{BoxStream, StreamExt};
use rand::{CryptoRng, RngCore};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tonic::Status;
use tracing::{debug, error, info, instrument, warn};

use crate::gatewaylnrpc::complete_htlcs_request::{Action, Cancel, Settle};
use crate::gatewaylnrpc::{
    route_htlc_request, route_htlc_response, CompleteHtlcsRequest, PayInvoiceRequest,
    PayInvoiceResponse, RouteHtlcRequest, RouteHtlcResponse, SubscribeInterceptHtlcsRequest,
    SubscribeInterceptHtlcsResponse,
};
use crate::lnrpc_client::ILnRpcClient;
use crate::rpc::{FederationInfo, GatewayRpcSender, LightningReconnectPayload};
use crate::utils::retry;
use crate::{GatewayError, Result};

/// How long a gateway announcement stays valid
const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);

#[derive(Clone)]
pub struct GatewayActor {
    client: Arc<GatewayClient>,
    pub lnrpc: Arc<RwLock<dyn ILnRpcClient>>,
    task_group: TaskGroup,
    gw_rpc: GatewayRpcSender,
    pub sender: Sender<Arc<AtomicBool>>,
}

#[derive(Debug, Clone)]
pub enum BuyPreimage {
    Internal((OutPoint, ContractId)),
    External(Preimage),
}

#[derive(Clone)]
struct LightningSenderStream {
    ln_sender: Sender<RouteHtlcRequest>,
    lnrpc: Arc<RwLock<dyn ILnRpcClient>>,
}

type RouteHTLCStream = BoxStream<'static, std::result::Result<RouteHtlcResponse, Status>>;

impl LightningSenderStream {
    async fn subscribe_to_htlcs(
        &self,
        short_channel_id: u64,
        ln_receiver: Receiver<RouteHtlcRequest>,
    ) -> Result<RouteHTLCStream> {
        let stream = self
            .lnrpc
            .write()
            .await
            .route_htlcs(ln_receiver.into())
            .await?;

        self.ln_sender
            .send(RouteHtlcRequest {
                action: Some(route_htlc_request::Action::SubscribeRequest(
                    SubscribeInterceptHtlcsRequest { short_channel_id },
                )),
            })
            .await
            .map_err(|_| GatewayError::Other(anyhow::anyhow!("Failed to subscribe to HTLCs")))?;

        info!(?short_channel_id, "Subscribed to HTLCs",);
        Ok(stream)
    }

    async fn settle_htlc(
        &self,
        preimage: Preimage,
        incoming_chan_id: u64,
        htlc_id: u64,
    ) -> Result<()> {
        info!(
            ?incoming_chan_id,
            ?htlc_id,
            "Successfully processed intercepted HTLC"
        );
        self.ln_sender
            .send(RouteHtlcRequest {
                action: Some(route_htlc_request::Action::CompleteRequest(
                    CompleteHtlcsRequest {
                        action: Some(Action::Settle(Settle {
                            preimage: preimage.0.to_vec(),
                        })),
                        incoming_chan_id,
                        htlc_id,
                    },
                )),
            })
            .await
            .map_err(|_| GatewayError::Other(anyhow::anyhow!("Failed to complete to HTLC")))
    }

    async fn cancel_htlc(
        &self,
        error_message: &str,
        incoming_chan_id: u64,
        htlc_id: u64,
    ) -> Result<()> {
        // Note: this specific complete htlc requires no further action.
        // If we fail to send the complete htlc message, or get an error
        // result, lightning node will still
        // cancel HTCL after expiry period lapses.
        // Result can be safely ignored.
        // TODO: make sure this succeeded?
        error!("{}", error_message);
        self.ln_sender
            .send(RouteHtlcRequest {
                action: Some(route_htlc_request::Action::CompleteRequest(
                    CompleteHtlcsRequest {
                        action: Some(Action::Cancel(Cancel {
                            reason: error_message.to_string(),
                        })),
                        incoming_chan_id,
                        htlc_id,
                    },
                )),
            })
            .await
            .map_err(|_| GatewayError::Other(anyhow::anyhow!("Failed to cancel to HTLC")))
    }
}

impl GatewayActor {
    pub async fn new(
        client: Arc<GatewayClient>,
        lnrpc: Arc<RwLock<dyn ILnRpcClient>>,
        route_hints: Vec<RouteHint>,
        task_group: TaskGroup,
        gw_rpc: GatewayRpcSender,
    ) -> Result<Self> {
        let register_client = client.clone();
        let mut tg = task_group.make_subgroup().await;
        tg.spawn("Register with federation", |_| async move {
            loop {
                // Retry gateway registration
                match retry(
                    String::from("Register With Federation"),
                    #[allow(clippy::unit_arg)]
                    || async {
                        let gateway_registration = register_client
                            .config()
                            .to_gateway_registration_info(route_hints.clone(), GW_ANNOUNCEMENT_TTL);
                        Ok(register_client
                            .register_with_federation(gateway_registration.clone())
                            .await?)
                    },
                    Duration::from_secs(1),
                    5,
                )
                .await
                {
                    Ok(_) => {
                        info!("Connected with federation");
                        tokio::time::sleep(GW_ANNOUNCEMENT_TTL / 2).await;
                    }
                    Err(e) => {
                        warn!("Failed to connect with federation: {}", e);
                        tokio::time::sleep(GW_ANNOUNCEMENT_TTL / 4).await;
                    }
                }
            }
        })
        .await;

        // Create a channel that will be used to shutdown the HTLC thread
        let (sender, receiver) = mpsc::channel::<Arc<AtomicBool>>(100);

        let mut actor = Self {
            client,
            lnrpc,
            task_group: tg,
            gw_rpc,
            sender,
        };

        actor.route_htlcs(receiver).await?;

        Ok(actor)
    }

    pub async fn stop_subscribing_htlcs(&mut self) -> Result<()> {
        self.sender
            .send(Arc::new(AtomicBool::new(true)))
            .await
            .map_err(|e| {
                GatewayError::Other(anyhow::anyhow!(
                    "Couldn't send shutdown signal to HTLC thread: {:?}",
                    e
                ))
            })
    }

    async fn wait_for_htlc_or_shutdown(
        stream: &mut RouteHTLCStream,
        receiver: &mut Receiver<Arc<AtomicBool>>,
        gw_rpc_copy: GatewayRpcSender,
    ) -> Option<RouteHtlcResponse> {
        tokio::select! {
            msg = stream.next() => match msg {
                Some(Ok(msg)) => Some(msg),
                Some(Err(e)) => {
                    warn!("Error sent over HTLC subscription: {}. Sending reconnect RPC", e);
                    // Sending a `LightningReconnectPayload` with `node_type` as None will use the existing
                    // credentials to reconnect to the same node.
                    let reconnect_req = LightningReconnectPayload { node_type: None };

                    // We swallow the error here and simply return `None` to alert the subscription thread that
                    // it should shutdown since we received an error from the lightning node.
                    let _ = gw_rpc_copy.send(reconnect_req).await.map_err(|e| {
                        warn!("Error sending reconnect RPC to gatewayd: {:?}", e);
                    });
                    None
                }
                None => {
                    warn!("HTLC stream closed by service");
                    None
                }
            },
            _ = receiver.recv() => {
                tracing::info!("Received signal to shutdown HTLC thread");
                None
            }
        }
    }

    async fn handle_intercepted_htlc(
        htlc: SubscribeInterceptHtlcsResponse,
        ln_sender: LightningSenderStream,
        actor: GatewayActor,
    ) -> Result<()> {
        let SubscribeInterceptHtlcsResponse {
            payment_hash,
            outgoing_amount_msat,
            incoming_chan_id,
            htlc_id,
            ..
        } = htlc;

        // TODO: Assert short channel id matches the one we subscribed to, or cancel
        // processing of intercepted HTLC TODO: Assert the offered
        // fee derived from invoice amount and outgoing amount is acceptable or
        // cancel processing of intercepted HTLC TODO:
        // Assert the HTLC expiry or cancel processing of
        // intercepted HTLC

        let hash = match sha256::Hash::from_slice(&payment_hash) {
            Ok(hash) => hash,
            Err(_) => {
                return ln_sender
                    .cancel_htlc("Failed to parse payment hash", incoming_chan_id, htlc_id)
                    .await;
            }
        };

        let amount_msat = Amount::from_msats(outgoing_amount_msat);

        let (outpoint, contract_id) = match actor
            .buy_preimage_from_federation(&hash, &amount_msat)
            .await
        {
            Ok((outpoint, contract_id)) => (outpoint, contract_id),
            Err(_) => {
                return ln_sender
                    .cancel_htlc("Failed to buy preimage", incoming_chan_id, htlc_id)
                    .await;
            }
        };

        match actor
            .pay_invoice_buy_preimage_finalize(BuyPreimage::Internal((outpoint, contract_id)))
            .await
        {
            Ok(preimage) => {
                return ln_sender
                    .settle_htlc(preimage, incoming_chan_id, htlc_id)
                    .await;
            }
            Err(_) => {
                return ln_sender
                    .cancel_htlc(
                        "Failed to process intercepted HTLC",
                        incoming_chan_id,
                        htlc_id,
                    )
                    .await;
            }
        }
    }

    pub async fn route_htlcs(
        &mut self,
        mut shutdown_receiver: Receiver<Arc<AtomicBool>>,
    ) -> Result<()> {
        let short_channel_id = self.client.config().mint_channel_id;

        // Create a stream used to communicate with the Lightning implementation
        let (sender, ln_receiver) = mpsc::channel::<RouteHtlcRequest>(100);
        let ln_sender = LightningSenderStream {
            ln_sender: sender,
            lnrpc: self.lnrpc.clone(),
        };

        let mut stream = ln_sender
            .subscribe_to_htlcs(short_channel_id, ln_receiver)
            .await?;

        let actor = self.to_owned();
        let gw_rpc_copy = self.gw_rpc.clone();

        self.task_group
            .spawn(
                "Subscribe to intercepted HTLCs in stream",
                move |handle| async move {
                    while let Some(RouteHtlcResponse {
                        action
                    }) = Self::wait_for_htlc_or_shutdown(
                        &mut stream,
                        &mut shutdown_receiver,
                        gw_rpc_copy.clone(),
                    )
                    .await
                    {
                        if handle.is_shutting_down() {
                            info!("Shutting down HTLC subscription");
                            break;
                        }

                        match action {
                            Some(route_htlc_response::Action::SubscribeResponse(htlc)) => {
                                Self::handle_intercepted_htlc(htlc, ln_sender.clone(), actor.clone()).await.expect("Error occurred while handling intercepted HTLC");
                            }
                            Some(route_htlc_response::Action::CompleteResponse(_complete_response)) => {
                                // TODO: Might need to add some error handling here
                                info!("Successfully handled HTLC");
                            }
                            None => {
                                error!("Error: Action received from Lightning node was None. This should never happen");
                            }
                        }
                    }
                }
            )
            .await;
        Ok(())
    }

    async fn fetch_all_notes(&self) {
        if let Err(e) = self.client.fetch_all_notes().await {
            debug!(error = %e, "Fetching notes failed");
        }
    }

    pub async fn buy_preimage_offer(
        &self,
        payment_hash: &sha256::Hash,
        amount: &Amount,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(OutPoint, ContractId)> {
        let (outpoint, contract_id) = self
            .client
            .buy_preimage_offer(payment_hash, amount, rng)
            .await?;
        Ok((outpoint, contract_id))
    }

    // TODO: Move this API to messaging
    pub async fn await_preimage_decryption(&self, outpoint: OutPoint) -> Result<Preimage> {
        let preimage = self.client.await_preimage_decryption(outpoint).await?;
        Ok(preimage)
    }

    #[instrument(skip_all, fields(%contract_id))]
    pub async fn pay_invoice(&self, contract_id: ContractId) -> Result<OutPoint> {
        self.pay_invoice_buy_preimage_finalize_and_claim(
            contract_id,
            self.pay_invoice_buy_preimage(contract_id).await?,
        )
        .await
    }

    #[instrument(skip_all, fields(%contract_id), err)]
    pub async fn pay_invoice_buy_preimage(&self, contract_id: ContractId) -> Result<BuyPreimage> {
        debug!("Fetching contract");
        let contract_account = self.client.fetch_outgoing_contract(contract_id).await?;

        let payment_params = match self
            .client
            .validate_outgoing_account(&contract_account)
            .await
        {
            Ok(payment_params) => payment_params,
            Err(e) => {
                self.client
                    .cancel_outgoing_contract(contract_account)
                    .await?;
                return Err(e.into());
            }
        };

        debug!(
            account = ?contract_account,
            "Fetched and validated contract account"
        );

        self.client
            .save_outgoing_payment(contract_account.clone())
            .await;

        let is_internal_payment = payment_params.maybe_internal
            && self
                .client
                .ln_client()
                .offer_exists(payment_params.payment_hash)
                .await
                .unwrap_or(false);

        Ok(if is_internal_payment {
            BuyPreimage::Internal(
                self.buy_preimage_from_federation(
                    &payment_params.payment_hash,
                    &payment_params.invoice_amount,
                )
                .await?,
            )
        } else {
            BuyPreimage::External(
                self.buy_preimage_over_lightning(
                    contract_account.contract.invoice,
                    &payment_params,
                )
                .await?,
            )
        })
    }

    pub async fn pay_invoice_buy_preimage_finalize(
        &self,
        buy_preimage: BuyPreimage,
    ) -> Result<Preimage> {
        match buy_preimage {
            BuyPreimage::Internal((out_point, contract_id)) => {
                self.buy_preimage_from_federation_await_decryption(out_point, contract_id)
                    .await
            }
            BuyPreimage::External(preimage) => Ok(preimage),
        }
    }

    #[instrument(skip_all, fields(?buy_preimage), err)]
    pub async fn pay_invoice_buy_preimage_finalize_and_claim(
        &self,
        contract_id: ContractId,
        buy_preimage: BuyPreimage,
    ) -> Result<OutPoint> {
        let rng = rand::rngs::OsRng;

        match self.pay_invoice_buy_preimage_finalize(buy_preimage).await {
            Ok(preimage) => {
                let outpoint = self
                    .client
                    .claim_outgoing_contract(contract_id, preimage, rng)
                    .await?;
                Ok(outpoint)
            }
            Err(e) => {
                warn!("Invoice payment failed. Aborting");
                // FIXME: combine both errors?
                self.client.abort_outgoing_payment(contract_id).await?;
                Err(e)
            }
        }
    }

    #[instrument(skip(self), ret, err)]
    pub async fn buy_preimage_from_federation(
        &self,
        payment_hash: &sha256::Hash,
        invoice_amount: &Amount,
    ) -> Result<(OutPoint, ContractId)> {
        let mut rng = rand::rngs::OsRng;

        self.fetch_all_notes().await;

        Ok(self
            .client
            .buy_preimage_offer(payment_hash, invoice_amount, &mut rng)
            .await?)
    }

    #[instrument(skip(self), ret, err)]
    pub async fn buy_preimage_from_federation_await_decryption(
        &self,
        out_point: OutPoint,
        contract_id: ContractId,
    ) -> Result<Preimage> {
        let rng = rand::rngs::OsRng;

        match self.client.await_preimage_decryption(out_point).await {
            Ok(preimage) => Ok(preimage),
            Err(error) => {
                warn!(%error, "Failed to decrypt preimage. Now requesting a refund");
                self.client
                    .refund_incoming_contract(contract_id, rng)
                    .await?;
                Err(GatewayError::ClientError(error))
            }
        }
    }

    pub async fn buy_preimage_over_lightning(
        &self,
        invoice: lightning_invoice::Invoice,
        payment_params: &PaymentParameters,
    ) -> Result<Preimage> {
        match self
            .lnrpc
            .read()
            .await
            .pay(PayInvoiceRequest {
                invoice: invoice.to_string(),
                max_delay: payment_params.max_delay,
                max_fee_percent: payment_params.max_fee_percent(),
            })
            .await
        {
            Ok(PayInvoiceResponse { preimage, .. }) => {
                let slice: [u8; 32] = preimage.try_into().expect("Failed to parse preimage");
                Ok(Preimage(slice))
            }
            Err(e) => Err(e),
        }
    }

    pub async fn await_outgoing_contract_claimed(
        &self,
        contract_id: ContractId,
        outpoint: OutPoint,
    ) -> Result<()> {
        Ok(self
            .client
            .await_outgoing_contract_claimed(contract_id, outpoint)
            .await?)
    }

    pub async fn get_deposit_address(&self) -> Result<Address> {
        let rng = rand::rngs::OsRng;
        Ok(self.client.get_new_pegin_address(rng).await)
    }

    pub async fn deposit(
        &self,
        txout_proof: TxOutProof,
        transaction: Transaction,
    ) -> Result<TransactionId> {
        let rng = rand::rngs::OsRng;

        self.client
            .peg_in(txout_proof, transaction, rng)
            .await
            .map_err(GatewayError::ClientError)
    }

    pub async fn withdraw(
        &self,
        amount: bitcoin::Amount,
        address: Address,
    ) -> Result<TransactionId> {
        self.fetch_all_notes().await;

        let rng = rand::rngs::OsRng;

        let peg_out = self
            .client
            .new_peg_out_with_fees(amount, address)
            .await
            .expect("Failed to create pegout with fees");
        self.client
            .peg_out(peg_out, rng)
            .await
            .map_err(GatewayError::ClientError)
            .map(|out_point| out_point.txid)
    }

    pub async fn backup(&self) -> Result<()> {
        self.client
            .mint_client()
            .back_up_ecash_to_federation()
            .await
            .map_err(GatewayError::Other)?;

        Ok(())
    }

    pub async fn restore(&self) -> Result<()> {
        // TODO: get the task group from `self`
        let mut task_group = TaskGroup::new();

        self.client
            .mint_client()
            .restore_ecash_from_federation(10, &mut task_group)
            .await
            .map_err(GatewayError::Other)?
            .map_err(|e| GatewayError::Other(e.into()))?;

        task_group
            .join_all(None)
            .await
            .map_err(GatewayError::Other)?;

        Ok(())
    }

    pub async fn get_balance(&self) -> Result<Amount> {
        self.fetch_all_notes().await;

        Ok(self.client.notes().await.total_amount())
    }

    pub fn get_info(&self) -> Result<FederationInfo> {
        let cfg = self.client.config();
        Ok(FederationInfo {
            federation_id: cfg.client_config.federation_id.clone(),
            mint_pubkey: cfg.redeem_key.x_only_public_key().0,
        })
    }
}
