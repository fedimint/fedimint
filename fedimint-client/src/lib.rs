//! This is a sketch/frame of future "modularized" fedimint client library
//!
//! It's not being used by anything yet.

use fedimint_api::Amount;
use fedimint_core_client::{ClientModule, ModuleKey, Output, SpendableOutput, Transaction};
use std::collections::BTreeMap;
use thiserror::Error;

/// Transaction, without a signature yet
pub struct UnsignedTransaction {
    pub inputs: Vec<SpendableOutput>,
    pub outputs: Vec<Output>,
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("your inputs are too low")]
    NotEnoughInputs,
}

impl UnsignedTransaction {
    /// Generate change outputs using `module`
    pub fn get_changed_needed(&mut self) -> Result<Amount, TransactionError> {
        todo!()
    }

    /// Sign into [`Transaction`] and return new [`SpendableOutput`]s
    pub fn sign(
        &self,
        _rng: &mut DeterministicRandomnessTracker,
    ) -> (Transaction, Vec<SpendableOutput>) {
        // check if inputs == outputs
        // validate input sigs?
        // calculate txid
        // convert all the `SpendableOutput`s to `Inputs`
        // use keys to sign tx
        todo!()
    }
}

/// Something that keeps tracks of which nonces (and any other deterministic randomness we need)
///
/// Details to be flushed out.
pub struct DeterministicRandomnessTracker;

#[derive(Default)]
pub struct Client {
    modules: BTreeMap<ModuleKey, ClientModule>,
}

#[derive(Debug, Error)]
pub enum DBError {
    #[error("not found")]
    NotFound,
}

impl Client {
    pub fn register_module(&mut self, module: ClientModule) -> &mut Self {
        if self.modules.insert(module.module_key(), module).is_some() {
            panic!("Must not register modules with key conflict");
        }
        self
    }

    pub fn register_module_with_id(&mut self, id: ModuleKey, module: ClientModule) -> &mut Self {
        if self.modules.insert(id, module).is_some() {
            panic!("Must not register modules with key conflict");
        }
        self
    }
}

/// Database transaaction object
///
/// Just a placeholder, don't pay too much attention to it.
pub struct DBTransaction;

impl DBTransaction {
    pub fn commit(&self) -> Result<(), DBError> {
        todo!()
    }
}
