use std::{sync::Arc, time::Duration};

use bitcoin::{Address, Transaction};
use bitcoin_hashes::sha256;
use fedimint_api::{Amount, OutPoint, TransactionId};
use fedimint_server::modules::{
    ln::contracts::{ContractId, Preimage},
    wallet::txoproof::TxOutProof,
};
use mint_client::{FederationId, GatewayClient, PaymentParameters};
use rand::{CryptoRng, RngCore};
use tracing::{debug, info, instrument, warn};

use crate::{ln::LnRpc, rpc::FederationInfo, utils::retry, LnGatewayError, Result};

pub struct GatewayActor {
    client: Arc<GatewayClient>,
}

impl GatewayActor {
    pub async fn new(client: Arc<GatewayClient>) -> Result<Self> {
        // Retry gateway registration
        match retry(
            String::from("Register With Federation"),
            #[allow(clippy::unit_arg)]
            || async {
                Ok(client
                    .register_with_federation(client.config().into())
                    .await
                    .expect("Failed to register with federation"))
            },
            Duration::from_secs(1),
            5,
        )
        .await
        {
            Ok(_) => info!("Registered with federation"),
            Err(e) => warn!("Failed to register with federation: {}", e),
        }

        Ok(Self { client })
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
    pub async fn pay_invoice(
        &self,
        ln_rpc: Arc<dyn LnRpc>,
        contract_id: ContractId,
    ) -> Result<OutPoint> {
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
            self.buy_preimage_external(ln_rpc, contract_account.contract.invoice, &payment_params)
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
        ln_rpc: Arc<dyn LnRpc>,
        invoice: lightning_invoice::Invoice,
        payment_params: &PaymentParameters,
    ) -> Result<Preimage> {
        match ln_rpc
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
            federation_id: FederationId(cfg.client_config.federation_name.clone()),
            mint_pubkey: cfg.redeem_key.x_only_public_key().0,
        })
    }
}
