use std::{sync::Arc, time::Duration};

use anyhow::anyhow;
use bitcoin::{Address, Transaction};
use bitcoin_hashes::{sha256, Hash};
use fedimint_api::{task::TaskGroup, Amount, OutPoint, TransactionId};
use fedimint_server::modules::{
    ln::contracts::{ContractId, Preimage},
    wallet::txoproof::TxOutProof,
};
use futures::StreamExt;
use mint_client::{GatewayClient, PaymentParameters};
use rand::{CryptoRng, RngCore};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    gatewaylnrpc::{
        complete_htlcs_request::{Action, Cancel, Settle},
        CompleteHtlcsRequest, PayInvoiceRequest, PayInvoiceResponse,
        SubscribeInterceptHtlcsRequest, SubscribeInterceptHtlcsResponse,
    },
    rpc::{lnrpc_client::DynLnRpcClient, FederationInfo},
    utils::retry,
    LnGatewayError, Result,
};

#[derive(Clone)]
pub struct GatewayActor {
    client: Arc<GatewayClient>,
    lnrpc: DynLnRpcClient,
    task_group: TaskGroup,
}

impl GatewayActor {
    pub async fn new(
        client: Arc<GatewayClient>,
        lnrpc: DynLnRpcClient,
        task_group: TaskGroup,
    ) -> Result<Self> {
        // Retry gateway registration
        match retry(
            String::from("Register With Federation"),
            #[allow(clippy::unit_arg)]
            || async {
                Ok(client
                    .register_with_federation(client.config().into())
                    .await?)
            },
            Duration::from_secs(1),
            5,
        )
        .await
        {
            Ok(_) => info!("Connected with federation"),
            Err(e) => warn!("Failed to connect with federation: {}", e),
        }

        let actor = Self {
            client,
            lnrpc,
            task_group,
        };

        actor.subscribe_htlcs().await?;

        Ok(actor)
    }

    async fn subscribe_htlcs(&self) -> Result<()> {
        let actor = self.to_owned();
        let lnrpc = self.lnrpc.to_owned();
        let short_channel_id = self.client.config().mint_channel_id;
        let mut tg = self.task_group.clone();

        let mut stream = lnrpc
            .subscribe_intercept_htlcs(SubscribeInterceptHtlcsRequest { short_channel_id })
            .await?;

        tg.spawn(
            "Subscribe to intercepted HTLCs in stream",
            move |subscription| async move {
                loop {
                    if subscription.is_shutting_down() {
                        info!("Shutting down HTLC handler");
                        // TODO: Unsubscribe from HTLCs?
                        break;
                    }

                    let mut htlc_outcomes = Vec::<CompleteHtlcsRequest>::new();

                    while let Some(SubscribeInterceptHtlcsResponse {
                        payment_hash,
                        outgoing_amount_msat,
                        intercepted_htlc_id,
                        ..
                    }) = match stream.message().await {
                        Ok(Some(msg)) => Some(msg),
                        Ok(None) => {
                            warn!("Stream closed");
                            None
                        }
                        Err(e) => {
                            warn!("Stream error: {:?}", e);
                            None
                        }
                    } {
                        // TODO: Assert short channel id matches the one we subscribed to, or cancel processing of intercepted HTLC
                        // TODO: Assert the offered fee derived from invoice amount and outgoing amount is acceptable or cancel processing of intercepted HTLC
                        // TODO: Assert the HTLC expiry or cancel processing of intercepted HTLC

                        let hash = match sha256::Hash::from_slice(&payment_hash) {
                            Ok(hash) => hash,
                            Err(e) => {
                                let fail = "Failed to parse payment hash";

                                error!("{}: {:?}", fail, e);
                                htlc_outcomes.push(CompleteHtlcsRequest {
                                    action: Some(Action::Cancel(Cancel {
                                        reason: fail.to_string(),
                                        intercepted_htlc_id,
                                    })),
                                });
                                continue;
                            }
                        };

                        let amount_msat = Amount::from_msats(outgoing_amount_msat);

                        let outcome = match actor.buy_preimage_internal(&hash, &amount_msat).await {
                            Ok(preimage) => {
                                info!("Successfully processed intercepted HTLC");
                                CompleteHtlcsRequest {
                                    action: Some(Action::Settle(Settle {
                                        preimage: preimage.0.to_vec(),
                                        intercepted_htlc_id,
                                    })),
                                }
                            }
                            Err(e) => {
                                error!("Failed to process intercepted HTLC: {:?}", e);
                                CompleteHtlcsRequest {
                                    action: Some(Action::Cancel(Cancel {
                                        reason: e.to_string(),
                                        intercepted_htlc_id,
                                    })),
                                }
                            }
                        };

                        htlc_outcomes.push(outcome);
                    }

                    if let Err(e) = lnrpc.complete_htlcs(htlc_outcomes).await {
                        error!("Failed to complete HTLCs: {:?}", e);
                        // NOTE: This is a potential loss of funds for the gateway.
                        // We should consider a retry of this operation, cancel the HTLCs or reclaim funds.
                    }
                }
            },
        )
        .await;

        Ok(())
    }

    async fn fetch_all_coins(&self) {
        for fetch_result in self.client.fetch_all_coins().await {
            if let Err(e) = fetch_result {
                debug!(error = %e, "Fetching coins failed")
            };
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
        debug!("Fetching contract");
        let rng = rand::rngs::OsRng;
        let contract_account = self.client.fetch_outgoing_contract(contract_id).await?;

        let payment_params = self
            .client
            .validate_outgoing_account(&contract_account)
            .await?;

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

        let preimage_res = if is_internal_payment {
            self.buy_preimage_internal(&payment_params.payment_hash, &payment_params.invoice_amount)
                .await
        } else {
            self.buy_preimage_external(contract_account.contract.invoice, &payment_params)
                .await
        };

        match preimage_res {
            Ok(preimage) => {
                let outpoint = self
                    .client
                    .claim_outgoing_contract(contract_id, preimage, rng)
                    .await?;

                Ok(outpoint)
            }
            Err(e) => {
                warn!("Invoice payment failed: {}. Aborting", e);
                // FIXME: combine both errors?
                self.client.abort_outgoing_payment(contract_id).await?;
                Err(e)
            }
        }
    }

    pub async fn buy_preimage_internal(
        &self,
        payment_hash: &sha256::Hash,
        invoice_amount: &Amount,
    ) -> Result<Preimage> {
        self.fetch_all_coins().await;

        let mut rng = rand::rngs::OsRng;
        let (out_point, contract_id) = self
            .client
            .buy_preimage_offer(payment_hash, invoice_amount, &mut rng)
            .await?;

        debug!("Awaiting decryption of preimage of hash {}", payment_hash);
        match self.client.await_preimage_decryption(out_point).await {
            Ok(preimage) => {
                debug!("Decrypted preimage {:?}", preimage);
                Ok(preimage)
            }
            Err(e) => {
                warn!("Failed to decrypt preimage. Now requesting a refund: {}", e);
                self.client
                    .refund_incoming_contract(contract_id, rng)
                    .await?;
                Err(LnGatewayError::ClientError(e))
            }
        }
    }

    pub async fn buy_preimage_external(
        &self,
        invoice: lightning_invoice::Invoice,
        payment_params: &PaymentParameters,
    ) -> Result<Preimage> {
        // TODO: Implement batch buy preimage external.
        // At present, we only send one invoice to the stream and expect a single response.

        let mut stream = self
            .lnrpc
            .pay_invoice(vec![PayInvoiceRequest {
                invoice: invoice.to_string(),
                max_delay: payment_params.max_delay,
                max_fee_percent: payment_params.max_fee_percent(),
            }])
            .await?;

        if let Some(response) = stream.next().await {
            return match response {
                Ok(PayInvoiceResponse { preimage, .. }) => {
                    let slice: [u8; 32] = preimage.try_into().expect("Failed to parse preimage");
                    Ok(Preimage(slice))
                }
                Err(status) => {
                    error!("Failed to pay invoice: {}", status.message());
                    Err(LnGatewayError::LnrpcError(status))
                }
            };
        }

        Err(LnGatewayError::Other(anyhow!(
            "No response from pay invoice"
        )))
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
            .map_err(LnGatewayError::ClientError)
    }

    pub async fn withdraw(
        &self,
        amount: bitcoin::Amount,
        address: Address,
    ) -> Result<TransactionId> {
        self.fetch_all_coins().await;

        let rng = rand::rngs::OsRng;

        let peg_out = self
            .client
            .new_peg_out_with_fees(amount, address)
            .await
            .expect("Failed to create pegout with fees");
        self.client
            .peg_out(peg_out, rng)
            .await
            .map_err(LnGatewayError::ClientError)
            .map(|out_point| out_point.txid)
    }

    pub async fn get_balance(&self) -> Result<Amount> {
        self.fetch_all_coins().await;

        Ok(self.client.coins().await.total_amount())
    }

    pub fn get_info(&self) -> Result<FederationInfo> {
        let cfg = self.client.config();
        Ok(FederationInfo {
            federation_id: cfg.client_config.federation_id.clone(),
            mint_pubkey: cfg.redeem_key.x_only_public_key().0,
        })
    }
}
