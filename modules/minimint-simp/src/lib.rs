pub mod config;
pub mod contracts;
mod db;

use crate::config::LightningModuleConfig;
use crate::contracts::{ContractId, IdentifyableContract};
use crate::db::{ContractKey, ContractUpdateKey};
use async_trait::async_trait;
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::Hash as BitcoinHash;
use minimint_api::db::batch::BatchTx;
use minimint_api::db::Database;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::module::interconnect::ModuleInterconect;
use minimint_api::module::ApiEndpoint;
use minimint_api::{Amount, FederationModule, PeerId};
use minimint_api::{InputMeta, OutPoint};
use secp256k1::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, instrument};

pub struct LightningModule {
    _cfg: LightningModuleConfig,
    db: Arc<dyn Database>,
}

/// A generic contract to hold money in a pub key locked account
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct AccountContract {
    pub amount: minimint_api::Amount,
    pub hash: Sha256,
}

impl IdentifyableContract for AccountContract {
    fn contract_id(&self) -> ContractId {
        let mut engine = ContractId::engine();
        Encodable::consensus_encode(self, &mut engine).expect("Hashing never fails");
        ContractId::from_engine(engine)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Preimage(pub [u8; 32]);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractInput {
    // Which account to spend from
    pub contract_id: contracts::ContractId,
    /// How sats to spend from this account
    pub amount: Amount,
    // Simplicity witness which provides a preimge
    pub witness: Preimage, // TODO: make simplicity understand this
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
        mut _batch: BatchTx<'a>,
        _consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
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
        _interconnect: &dyn ModuleInterconect,
        _cache: &Self::VerificationCache,
        input: &'a Self::TxInput,
    ) -> Result<InputMeta<'a>, Self::Error> {
        let account: AccountContract = self
            .get_contract_account(input.contract_id)
            .ok_or(LightningModuleError::UnknownContract(input.contract_id))?;

        if account.amount < input.amount {
            return Err(LightningModuleError::InsufficientFunds(
                account.amount,
                input.amount,
            ));
        }

        // TODO: call simplicity
        if account.hash != Sha256::hash(&input.witness.0) {
            return Err(LightningModuleError::BadHash);
        }

        Ok(InputMeta {
            amount: input.amount,
            puk_keys: Box::new(std::iter::empty()),
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

        let account_db_key = ContractKey(input.contract_id);
        let mut contract_account = self
            .db
            .get_value(&account_db_key)
            .expect("DB error")
            .expect("Should fail validation if contract account doesn't exist");

        // FIXME: should we be checking that this isn't negative???
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
                hash: contract.hash.clone(),
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
        mut _batch: BatchTx<'a>,
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
    pub fn new(_cfg: LightningModuleConfig, db: Arc<dyn Database>) -> LightningModule {
        LightningModule { _cfg, db }
    }
    pub fn get_contract_account(&self, contract_id: ContractId) -> Option<AccountContract> {
        self.db
            .get_value(&ContractKey(contract_id))
            .expect("DB error")
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LightningModuleError {
    #[error("The the input contract {0} does not exist")]
    UnknownContract(ContractId),
    #[error("The input contract has too little funds, got {0}, input spends {1}")]
    InsufficientFunds(Amount, Amount),
    #[error("Output contract value may not be zero unless it's an offer output")]
    ZeroOutput,
    #[error("Hash doesn't match")]
    BadHash,
}
