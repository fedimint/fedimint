pub mod config;
pub mod contracts;
mod db;

use crate::config::LightningModuleConfig;
use crate::contracts::{ContractId, IdentifyableContract};
use crate::db::{ContractKey, ContractUpdateKey};
use async_trait::async_trait;
use bitcoin_hashes::Hash as BitcoinHash;
use minimint_api::db::batch::BatchTx;
use minimint_api::db::Database;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::module::interconnect::ModuleInterconect;
use minimint_api::module::{http, ApiEndpoint};
use minimint_api::{Amount, FederationModule, PeerId};
use minimint_api::{InputMeta, OutPoint};
use secp256k1::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, instrument};

pub struct LightningModule {
    cfg: LightningModuleConfig,
    db: Arc<dyn Database>,
}

/// A generic contract to hold money in a pub key locked account
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct AccountContract {
    pub amount: minimint_api::Amount,
    pub key: secp256k1::schnorrsig::PublicKey,
}

impl IdentifyableContract for AccountContract {
    fn contract_id(&self) -> ContractId {
        let mut engine = ContractId::engine();
        Encodable::consensus_encode(self, &mut engine).expect("Hashing never fails");
        ContractId::from_engine(engine)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractInput {
    pub crontract_id: contracts::ContractId,
    /// While for now we only support spending the entire contract we need to avoid
    pub amount: Amount,
    /// Of the three contract types only the outgoing one needs any other witness data than a
    /// signature. The signature is aggregated on the transaction level, so only the optional
    /// preimage remains.
    // pub witness: Option<contracts::outgoing::Preimage>,
    pub witness: Option<String>, // FIXME
}

#[async_trait(?Send)]
impl FederationModule for LightningModule {
    type Error = LightningModuleError;
    type TxInput = ContractInput;
    type TxOutput = AccountContract;
    type TxOutputOutcome = ContractId;
    type ConsensusItem = ();
    type VerificationCache = ();

    async fn consensus_proposal<'a>(
        &'a self,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<Self::ConsensusItem> {
        vec![]
    }

    async fn begin_consensus_epoch<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) {
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a Self::TxInput>,
    ) -> Self::VerificationCache {
    }

    fn validate_input<'a>(
        &self,
        interconnect: &dyn ModuleInterconect,
        _cache: &Self::VerificationCache,
        input: &'a Self::TxInput,
    ) -> Result<InputMeta<'a>, Self::Error> {
        let account: AccountContract = self
            .get_contract_account(input.crontract_id)
            .ok_or(LightningModuleError::UnknownContract(input.crontract_id))?;

        if account.amount < input.amount {
            return Err(LightningModuleError::InsufficientFunds(
                account.amount,
                input.amount,
            ));
        }
        Ok(InputMeta {
            amount: input.amount,
            puk_keys: Box::new(std::iter::once(account.key)),
        })
    }

    fn apply_input<'a, 'b>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        mut batch: BatchTx<'a>,
        input: &'b Self::TxInput,
        cache: &Self::VerificationCache,
    ) -> Result<InputMeta<'b>, Self::Error> {
        let meta = self.validate_input(interconnect, cache, input)?;

        let account_db_key = ContractKey(input.crontract_id);
        let mut contract_account = self
            .db
            .get_value(&account_db_key)
            .expect("DB error")
            .expect("Should fail validation if contract account doesn't exist");
        contract_account.amount -= meta.amount;
        batch.append_insert(account_db_key, contract_account);

        batch.commit();
        Ok(meta)
    }

    fn validate_output(&self, output: &Self::TxOutput) -> Result<Amount, Self::Error> {
        let contract = output;
        if contract.amount == Amount::ZERO {
            Err(LightningModuleError::ZeroOutput)
        } else {
            Ok(contract.amount)
        }
    }

    fn apply_output<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        output: &'a Self::TxOutput,
        out_point: OutPoint,
    ) -> Result<Amount, Self::Error> {
        let amount = self.validate_output(output)?;
        let contract = output;

        // Set a balance on this account
        let contract_db_key = ContractKey(contract.contract_id());
        let updated_contract_account = self
            .db
            .get_value(&contract_db_key)
            .expect("DB error")
            .map(|mut value: AccountContract| {
                value.amount += amount;
                value
            })
            .unwrap_or_else(|| AccountContract {
                amount,
                key: contract.key.clone(),
            });
        batch.append_insert(contract_db_key, updated_contract_account);

        batch.append_insert_new(ContractUpdateKey(out_point), contract.contract_id());

        batch.commit();
        Ok(amount)
    }

    #[instrument(skip_all)]
    async fn end_consensus_epoch<'a>(
        &'a self,
        _consensus_peers: &HashSet<PeerId>,
        mut batch: BatchTx<'a>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<PeerId> {
        // FIXME: use this to drop peers with conflicting simplicity contract IDs
        vec![]
    }

    fn output_status(&self, out_point: OutPoint) -> Option<Self::TxOutputOutcome> {
        self.db
            .get_value(&ContractUpdateKey(out_point))
            .expect("DB error")
    }

    fn api_base_name(&self) -> &'static str {
        "ln"
    }

    fn api_endpoints(&self) -> &'static [ApiEndpoint<Self>] {
        &[]
    }
}

impl LightningModule {
    pub fn new(cfg: LightningModuleConfig, db: Arc<dyn Database>) -> LightningModule {
        LightningModule { cfg, db }
    }
    pub fn get_contract_account(&self, contract_id: ContractId) -> Option<AccountContract> {
        self.db
            .get_value(&ContractKey(contract_id))
            .expect("DB error")
    }
}

fn block_height(interconnect: &dyn ModuleInterconect) -> u32 {
    // This is a future because we are normally reading from a network socket. But for internal
    // calls the data is available instantly in one go, so we can just block on it.
    futures::executor::block_on(
        interconnect
            .call(
                "wallet",
                "/block_height".to_owned(),
                http::Method::Get,
                Default::default(),
            )
            .expect("Wallet module not present or malfunctioning!")
            .body_json(),
    )
    .expect("Malformed block height response from wallet module!")
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LightningModuleError {
    #[error("The the input contract {0} does not exist")]
    UnknownContract(ContractId),
    #[error("The input contract has too little funds, got {0}, input spends {1}")]
    InsufficientFunds(Amount, Amount),
    #[error("An outgoing LN contract spend did not provide a preimage")]
    MissingPreimage,
    #[error("An outgoing LN contract spend provided a wrong preimage")]
    InvalidPreimage,
    #[error("Incoming contract not ready to be spent yet, decryption in progress")]
    ContractNotReady,
    #[error("Output contract value may not be zero unless it's an offer output")]
    ZeroOutput,
    #[error("Offer contains invalid threshold-encrypted data")]
    InvalidEncryptedPreimage,
    #[error(
        "The incoming LN account requires more funding according to the offer (need {0} got {1})"
    )]
    InsufficientIncomingFunding(Amount, Amount),
    #[error("No offer found for payment hash {0}")]
    NoOffer(secp256k1::hashes::sha256::Hash),
}
