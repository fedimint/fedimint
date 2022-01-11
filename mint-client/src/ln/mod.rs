mod db;
mod gateway;
mod outgoing;

use crate::api::FederationApi;
use crate::ln::db::OutgoingPaymentKey;
use crate::ln::gateway::LightningGateway;
use crate::ln::outgoing::OutgoingContractData;
use lightning_invoice::Invoice;
use minimint::modules::ln;
use minimint::modules::ln::contracts::outgoing::OutgoingContract;
use minimint::modules::ln::contracts::{Contract, IdentifyableContract};
use minimint::modules::ln::{ContractOrOfferOutput, ContractOutput};
use minimint_api::db::batch::BatchTx;
use minimint_api::db::RawDatabase;
use minimint_api::Amount;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use thiserror::Error;

pub struct LnClient {
    pub db: Arc<dyn RawDatabase>,
    pub cfg: ln::config::LightningModuleClientConfig,
    pub api: Arc<dyn FederationApi>,
    pub secp: secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
}

#[allow(dead_code)]
impl LnClient {
    /// Create an output that incentivizes a Lighning gateway to pay an invoice for us. It has time
    /// till the block height defined by `timelock`, after that we can claim our money back.
    pub async fn create_outgoing_output<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        invoice: Invoice,
        gateway: &LightningGateway,
        timelock: u32,
        mut rng: impl RngCore + CryptoRng + 'a,
    ) -> Result<ContractOrOfferOutput> {
        let contract_amount = {
            let invoice_amount_msat = invoice
                .amount_milli_satoshis()
                .ok_or(LnClientError::MissingInvoiceAmount)?;
            // TODO: better define fee handling
            // Add 1% fee margin
            let contract_amount_msat = invoice_amount_msat + (invoice_amount_msat / 100);
            Amount::from_msat(contract_amount_msat)
        };

        let user_sk = secp256k1_zkp::schnorrsig::KeyPair::new(&self.secp, &mut rng);

        let contract = OutgoingContract {
            hash: *invoice.payment_hash(),
            gateway_key: gateway.mint_pub_key,
            timelock,
            user_key: secp256k1_zkp::schnorrsig::PublicKey::from_keypair(&self.secp, &user_sk),
            invoice: invoice.to_string(),
        };

        let outgoing_payment = OutgoingContractData {
            recovery_key: user_sk,
            contract: contract.clone(),
        };

        batch.append_insert_new(OutgoingPaymentKey(contract.contract_id()), outgoing_payment);

        Ok(ContractOrOfferOutput::Contract(ContractOutput {
            amount: contract_amount,
            contract: Contract::Outgoing(contract),
        }))
    }
}

pub type Result<T> = std::result::Result<T, LnClientError>;

#[derive(Debug, Error)]
pub enum LnClientError {
    #[error("We can't pay an amountless invoice")]
    MissingInvoiceAmount,
}
