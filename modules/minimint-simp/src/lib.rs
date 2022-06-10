pub mod config;
mod db;

use crate::config::SimplicityModuleConfig;
use crate::db::{ProgramKey, ProgramUpdateKey};
use async_trait::async_trait;
use minimint_api::db::batch::BatchTx;
use minimint_api::db::Database;
use minimint_api::encoding::{Decodable, DecodeError, Encodable};
use minimint_api::module::interconnect::ModuleInterconect;
use minimint_api::module::ApiEndpoint;
use minimint_api::{Amount, FederationModule, PeerId};
use minimint_api::{InputMeta, OutPoint};
use secp256k1::rand::{CryptoRng, RngCore};
use simplicity::exec::BitMachine;
use simplicity::extension::jets::JetsNode;
use simplicity::Program;
use std::collections::HashSet;
use std::io::Error;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, instrument};

pub struct SimplicityModule {
    _cfg: SimplicityModuleConfig,
    db: Arc<dyn Database>,
}

/// Simplicity CMR
#[derive(Debug, Clone, Eq, PartialEq, Hash, Copy)]
pub struct ProgramId(pub [u8; 32]);

impl Encodable for ProgramId {
    fn consensus_encode<W: std::io::Write>(&self, writer: W) -> Result<usize, Error> {
        self.0.consensus_encode(writer)
    }
}

impl Decodable for ProgramId {
    fn consensus_decode<D: std::io::Read>(d: D) -> Result<Self, DecodeError> {
        Ok(ProgramId(Decodable::consensus_decode(d)?))
    }
}

/// A generic contract to hold money in an account locked by a Simplicity program
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct Account {
    pub amount: minimint_api::Amount,
    pub program_id: ProgramId,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Input {
    // Which account to spend from
    pub program_id: ProgramId,
    /// How sats to spend from this account
    pub amount: Amount,
    // Simplicity program
    pub program: Program<JetsNode>,
}

#[async_trait(?Send)]
impl FederationModule for SimplicityModule {
    type Error = SimplicityModuleError;
    type TxInput = Input;
    type TxOutput = Account;
    type TxOutputOutcome = ProgramId;
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
        let account: Account = self
            .get_account(input.program_id)
            .ok_or(SimplicityModuleError::UnknownProgram(input.program_id))?;

        if account.amount < input.amount {
            return Err(SimplicityModuleError::InsufficientFunds(
                account.amount,
                input.amount,
            ));
        }

        let program_matches = input.program_id.0.as_ref() == input.program.root_node().cmr.as_ref();
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

        let account_db_key = ProgramKey(input.program_id);
        let mut account = self
            .db
            .get_value(&account_db_key)
            .expect("DB error")
            .expect("Should fail validation if account doesn't exist");

        // FIXME: should we be checking that this isn't negative???
        account.amount -= meta.amount;

        // Save simplicity program CMR
        batch.append_insert(account_db_key, account);

        batch.commit();
        Ok(meta)
    }

    fn validate_output(&self, output: &Self::TxOutput) -> Result<Amount, Self::Error> {
        if output.amount == Amount::ZERO {
            Err(SimplicityModuleError::ZeroOutput)
        } else {
            Ok(output.amount)
        }
    }

    fn apply_output<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        output: &'a Self::TxOutput,
        out_point: OutPoint,
    ) -> Result<Amount, Self::Error> {
        let amount = self.validate_output(output)?;

        // Set a balance on this account
        let program_db_key = ProgramKey(output.program_id);
        let updated_account = self
            .db
            .get_value(&program_db_key)
            .expect("DB error")
            .map(|mut value: Account| {
                value.amount += amount;
                value
            })
            .unwrap_or_else(|| Account {
                amount,
                program_id: output.program_id,
            });
        batch.append_insert(program_db_key, updated_account);

        batch.append_insert_new(ProgramUpdateKey(out_point), output.program_id);

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
            .get_value(&ProgramUpdateKey(out_point))
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
    pub fn get_account(&self, program_id: ProgramId) -> Option<Account> {
        self.db
            .get_value(&ProgramKey(program_id))
            .expect("DB error")
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SimplicityModuleError {
    #[error("The the input program does not exist")]
    UnknownProgram(ProgramId),
    #[error("The account has too little funds, got {0}, input spends {1}")]
    InsufficientFunds(Amount, Amount),
    #[error("Output value may not be zero")]
    ZeroOutput,
    #[error("Hash doesn't match")]
    BadHash,
    #[error("Simplicity error")]
    SimplicityError,
}
