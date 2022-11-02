use std::sync::Arc;

use bitcoin::{Address, Transaction};
use bitcoin_hashes::sha256;
use fedimint_api::{Amount, OutPoint, TransactionId};
use fedimint_server::modules::{
    ln::contracts::{ContractId, Preimage},
    wallet::txoproof::TxOutProof,
};
use mint_client::{GatewayClient, PaymentParameters};
use rand::{CryptoRng, RngCore};
use tracing::{debug, instrument, warn};

use crate::{ln::LnRpc, LnGatewayError, Result};

pub struct GatewayActor {
    client: Arc<GatewayClient>,
}

impl GatewayActor {
    pub async fn new(client: Arc<GatewayClient>) -> Result<Self> {
        // Regster gateway actor with federation
        // FIXME: This call is critically dependent on the federation being up and running.
        // We should either use a retry strategy, OR register federations on the gateway at runtime
        // as proposed in https://github.com/fedimint/fedimint/issues/699
        client
            .register_with_federation(client.config().into())
            .await
            .expect("Failed to register with federation");

        Ok(Self { client })
    }

    /// Fetch all coins minted for this gateway by the federation
    pub async fn fetch_all_coins(&self) {
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

        self.client.save_outgoing_payment(contract_account.clone());

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
            self.buy_preimage_external(ln_rpc, &contract_account.contract.invoice, &payment_params)
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
        invoice: &str,
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

    pub fn get_deposit_address(&self) -> Result<Address> {
        let mut rng = rand::rngs::OsRng;
        Ok(self.client.get_new_pegin_address(&mut rng))
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
        self.client
            .fetch_all_coins()
            .await
            .into_iter()
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(self.client.coins().total_amount())
    }
}
