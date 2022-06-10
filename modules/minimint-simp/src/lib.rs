pub mod config;
pub mod contracts;
mod db;

use crate::config::SimplicityModuleConfig;
use crate::contracts::ContractId;
use crate::db::{ContractKey, ContractUpdateKey};
use async_trait::async_trait;
use minimint_api::db::batch::BatchTx;
use minimint_api::db::Database;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::module::interconnect::ModuleInterconect;
use minimint_api::module::ApiEndpoint;
use minimint_api::{Amount, FederationModule, PeerId};
use minimint_api::{InputMeta, OutPoint};
use secp256k1::rand::{CryptoRng, RngCore};
use simplicity::exec::BitMachine;
use simplicity::extension::jets::JetsNode;
use simplicity::Program;
use std::collections::HashSet;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, instrument};

pub struct SimplicityModule {
    _cfg: SimplicityModuleConfig,
    db: Arc<dyn Database>,
}

/// A generic contract to hold money in a pub key locked account
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct AccountContract {
    pub amount: minimint_api::Amount,
    pub id: ContractId,
}

// #[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
#[derive(Debug, Eq, PartialEq)]
pub struct ContractInput {
    // Which account to spend from
    pub contract_id: ContractId,
    /// How sats to spend from this account
    pub amount: Amount,
    // Simplicity program
    pub program: Program<JetsNode>,
}

#[async_trait(?Send)]
impl FederationModule for SimplicityModule {
    type Error = SimplicityModuleError;
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
            .ok_or(SimplicityModuleError::UnknownContract(input.contract_id))?;

        if account.amount < input.amount {
            return Err(SimplicityModuleError::InsufficientFunds(
                account.amount,
                input.amount,
            ));
        }

        let program_matches =
            input.contract_id.0.as_ref() == input.program.root_node().cmr.as_ref();
        if !program_matches {
            return Err(SimplicityModuleError::BadHash);
        }

        let mut machine = BitMachine::for_program(&input.program);
        machine
            .exec(&input.program, &())
            .map_err(|_| SimplicityModuleError::SimplicityError)?;

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

        // Save simplicity program CMR
        batch.append_insert(account_db_key, contract_account);

        batch.commit();
        Ok(meta)
    }

    fn validate_output(&self, output: &Self::TxOutput) -> Result<Amount, Self::Error> {
        let contract = output;
        if contract.amount == Amount::ZERO {
            Err(SimplicityModuleError::ZeroOutput)
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
        let contract_db_key = ContractKey(contract.id);
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
                id: contract.id,
            });
        batch.append_insert(contract_db_key, updated_contract_account);

        batch.append_insert_new(ContractUpdateKey(out_point), contract.id);

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
        "simp"
    }

    fn api_endpoints(&self) -> &'static [ApiEndpoint<Self>] {
        &[]
    }
}

impl SimplicityModule {
    pub fn new(_cfg: SimplicityModuleConfig, db: Arc<dyn Database>) -> SimplicityModule {
        SimplicityModule { _cfg, db }
    }
    pub fn get_contract_account(&self, contract_id: ContractId) -> Option<AccountContract> {
        self.db
            .get_value(&ContractKey(contract_id))
            .expect("DB error")
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SimplicityModuleError {
    #[error("The the input contract does not exist")]
    UnknownContract(ContractId),
    #[error("The input contract has too little funds, got {0}, input spends {1}")]
    InsufficientFunds(Amount, Amount),
    #[error("Output contract value may not be zero unless it's an offer output")]
    ZeroOutput,
    #[error("Hash doesn't match")]
    BadHash,
    #[error("Simplicity error")]
    SimplicityError,
}
