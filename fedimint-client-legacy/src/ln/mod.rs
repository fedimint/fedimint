// TODO: once user and mint client are merged, make this private again
pub mod db;
pub mod incoming;
pub mod outgoing;

use std::sync::Arc;
use std::time::Duration;

use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_core::api::FederationError;
use fedimint_core::config::FederationId;
use fedimint_core::core::client::ClientModule;
use fedimint_core::core::Decoder;
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::module::{ModuleCommon, TransactionItemAmount};
use fedimint_core::task::timeout;
use fedimint_core::Amount;
use futures::StreamExt;
use lightning::routing::gossip::RoutingFees;
use lightning_invoice::Bolt11Invoice;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use self::db::ConfirmedInvoiceKey;
use self::incoming::ConfirmedInvoice;
use crate::api::{LnFederationApi, WalletFederationApi};
use crate::ln::db::{OutgoingPaymentKey, OutgoingPaymentKeyPrefix};
use crate::ln::incoming::IncomingContractAccount;
use crate::ln::outgoing::{OutgoingContractAccount, OutgoingContractData};
use crate::modules::ln::config::LightningClientConfig;
use crate::modules::ln::contracts::incoming::IncomingContractOffer;
use crate::modules::ln::contracts::outgoing::OutgoingContract;
use crate::modules::ln::contracts::{
    Contract, ContractId, EncryptedPreimage, FundedContract, IdentifiableContract, Preimage,
};
use crate::modules::ln::{
    ContractAccount, ContractOutput, LightningGateway, LightningInput, LightningModuleTypes,
    LightningOutput,
};
use crate::utils::ClientContext;

#[derive(Debug)]
pub struct LnClient {
    pub config: LightningClientConfig,
    pub context: Arc<ClientContext>,
}

impl ClientModule for LnClient {
    const KIND: &'static str = "ln";
    type Module = LightningModuleTypes;

    fn decoder(&self) -> Decoder {
        <Self::Module as ModuleCommon>::decoder()
    }

    fn input_amount(&self, input: &LightningInput) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: input.amount,
            fee: self.config.fee_consensus.contract_input,
        }
    }

    fn output_amount(&self, output: &LightningOutput) -> TransactionItemAmount {
        match output {
            LightningOutput::Contract(account_output) => TransactionItemAmount {
                amount: account_output.amount,
                fee: self.config.fee_consensus.contract_output,
            },
            LightningOutput::Offer(_) | LightningOutput::CancelOutgoing { .. } => {
                TransactionItemAmount {
                    amount: Amount::ZERO,
                    fee: Amount::ZERO,
                }
            }
        }
    }
}

#[allow(dead_code)]
impl LnClient {
    /// Create an output that incentivizes a Lighning gateway to pay an invoice
    /// for us. It has time till the block height defined by `timelock`,
    /// after that we can claim our money back.
    pub async fn create_outgoing_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        invoice: Bolt11Invoice,
        gateway: &LightningGateway,
        timelock: u32,
        mut rng: impl RngCore + CryptoRng + 'a,
    ) -> Result<LightningOutput> {
        let contract_amount = self.compute_outgoing_contract_amount(&invoice, gateway.fees)?;

        let user_sk = bitcoin::KeyPair::new(&self.context.secp, &mut rng);

        let contract = OutgoingContract {
            hash: *invoice.payment_hash(),
            gateway_key: gateway.gateway_redeem_key,
            timelock,
            user_key: user_sk.x_only_public_key().0,
            invoice,
            cancelled: false,
        };

        let outgoing_payment = OutgoingContractData {
            recovery_key: user_sk,
            contract_account: OutgoingContractAccount {
                amount: contract_amount,
                contract: contract.clone(),
            },
        };

        dbtx.insert_new_entry(
            &OutgoingPaymentKey(contract.contract_id()),
            &outgoing_payment,
        )
        .await;

        Ok(LightningOutput::Contract(ContractOutput {
            amount: contract_amount,
            contract: Contract::Outgoing(contract),
        }))
    }

    pub async fn get_contract_account(&self, id: ContractId) -> Result<ContractAccount> {
        timeout(Duration::from_secs(30), self.context.api.fetch_contract(id))
            .await
            .map_err(|_e| LnClientError::Timeout)?
            .map_err(LnClientError::ApiError)
    }

    pub async fn get_outgoing_contract(&self, id: ContractId) -> Result<OutgoingContractAccount> {
        let account = self.get_contract_account(id).await?;
        match account.contract {
            FundedContract::Outgoing(c) => Ok(OutgoingContractAccount {
                amount: account.amount,
                contract: c,
            }),
            _ => Err(LnClientError::WrongAccountType),
        }
    }

    /// Determines if an outgoing contract can be refunded
    pub async fn is_outgoing_contract_refundable(&self, id: ContractId) -> Result<bool> {
        let contract = self.get_outgoing_contract(id).await?;

        // If the contract was cancelled by the LN gateway we can get a refund instantly
        // …
        if contract.contract.cancelled {
            return Ok(true);
        }

        // … otherwise we have to wait till the timeout hits
        let consensus_block_count = self
            .context
            .api
            .fetch_consensus_block_count()
            .await
            .map_err(LnClientError::ApiError)?;
        if (contract.contract.timelock as u64) < consensus_block_count {
            return Ok(true);
        }

        Ok(false)
    }

    /// Waits for an outgoing contract to become refundable
    pub async fn await_outgoing_refundable(&self, id: ContractId) -> Result<()> {
        while !self.is_outgoing_contract_refundable(id).await? {
            crate::sleep(Duration::from_secs(1)).await;
        }
        Ok(())
    }

    pub async fn get_incoming_contract(&self, id: ContractId) -> Result<IncomingContractAccount> {
        let account = self.get_contract_account(id).await?;
        match account.contract {
            FundedContract::Incoming(c) => Ok(IncomingContractAccount {
                amount: account.amount,
                contract: c.contract,
            }),
            _ => Err(LnClientError::WrongAccountType),
        }
    }

    pub async fn refundable_outgoing_contracts(
        &self,
        block_count: u64,
    ) -> Vec<OutgoingContractData> {
        // TODO: unify block height type
        self.context
            .db
            .begin_transaction()
            .await
            .find_by_prefix(&OutgoingPaymentKeyPrefix)
            .await
            .filter_map(|(_, outgoing_data)| async {
                let cancelled = outgoing_data.contract_account.contract.cancelled;
                let timed_out =
                    (outgoing_data.contract_account.contract.timelock as u64) < block_count;
                if cancelled || timed_out {
                    Some(outgoing_data)
                } else {
                    None
                }
            })
            .collect::<Vec<OutgoingContractData>>()
            .await
    }

    pub fn create_refund_outgoing_contract_input<'a>(
        &self,
        contract_data: &'a OutgoingContractData,
    ) -> (&'a bitcoin::KeyPair, LightningInput) {
        (
            &contract_data.recovery_key,
            contract_data.contract_account.refund(),
        )
    }

    pub fn create_offer_output(
        &self,
        amount: Amount,
        payment_hash: Sha256Hash,
        payment_secret: Preimage,
        expiry_time: Option<u64>,
    ) -> LightningOutput {
        LightningOutput::Offer(IncomingContractOffer {
            amount,
            hash: payment_hash,
            encrypted_preimage: EncryptedPreimage::new(
                payment_secret,
                &self.config.threshold_pub_key,
            ),
            expiry_time,
        })
    }

    pub async fn get_offer(&self, payment_hash: Sha256Hash) -> Result<IncomingContractOffer> {
        timeout(
            Duration::from_secs(10),
            self.context.api.fetch_offer(payment_hash),
        )
        .await
        .map_err(|_e| LnClientError::Timeout)?
        .map_err(LnClientError::ApiError)
    }

    pub async fn offer_exists(&self, payment_hash: Sha256Hash) -> Result<bool> {
        self.context
            .api
            .offer_exists(payment_hash)
            .await
            .map_err(LnClientError::ApiError)
    }

    pub async fn save_confirmed_invoice(&self, invoice: &ConfirmedInvoice) {
        let mut dbtx = self.context.db.begin_transaction().await;
        dbtx.insert_entry(&ConfirmedInvoiceKey(invoice.contract_id()), invoice)
            .await;
        dbtx.commit_tx().await;
    }

    pub async fn get_confirmed_invoice(&self, contract_id: ContractId) -> Result<ConfirmedInvoice> {
        let confirmed_invoice = self
            .context
            .db
            .begin_transaction()
            .await
            .get_value(&ConfirmedInvoiceKey(contract_id))
            .await
            .ok_or(LnClientError::NoConfirmedInvoice(contract_id))?;
        Ok(confirmed_invoice)
    }

    /// Used by gateway to prematurely return funds to the user if the payment
    /// failed
    pub fn create_cancel_outgoing_output(
        &self,
        contract_id: ContractId,
        signature: secp256k1_zkp::schnorr::Signature,
    ) -> LightningOutput {
        LightningOutput::CancelOutgoing {
            contract: contract_id,
            gateway_signature: signature,
        }
    }

    pub fn compute_outgoing_contract_amount(
        &self,
        invoice: &Bolt11Invoice,
        fees: RoutingFees,
    ) -> Result<Amount> {
        let invoice_amount_msat = invoice
            .amount_milli_satoshis()
            .ok_or(LnClientError::MissingInvoiceAmount)?;

        let base_fee = fees.base_msat as u64;
        let margin_fee: u64 = if fees.proportional_millionths > 0 {
            let fee_percent = 1000000 / fees.proportional_millionths as u64;
            invoice_amount_msat / fee_percent
        } else {
            0
        };

        // Add base and margin routing fees
        let contract_amount_msat = invoice_amount_msat + base_fee + margin_fee;

        Ok(Amount::from_msats(contract_amount_msat))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PayInvoicePayload {
    pub federation_id: FederationId,
    pub contract_id: ContractId,
}

impl PayInvoicePayload {
    pub fn new(federation_id: FederationId, contract_id: ContractId) -> Self {
        Self {
            contract_id,
            federation_id,
        }
    }
}

pub type Result<T> = std::result::Result<T, LnClientError>;

#[derive(Debug, Error)]
pub enum LnClientError {
    #[error("We can't pay an amountless invoice")]
    MissingInvoiceAmount,
    #[error("Mint API error: {0}")]
    ApiError(FederationError),
    #[error("Timeout")]
    Timeout,
    #[error("Mint returned unexpected account type")]
    WrongAccountType,
    #[error("No ConfirmedOffer found for contract ID {0}")]
    NoConfirmedInvoice(ContractId),
}
