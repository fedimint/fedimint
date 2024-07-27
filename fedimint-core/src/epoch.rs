use anyhow::ensure;
use fedimint_core::core::DynModuleConsensusItem as ModuleConsensusItem;
use fedimint_core::encoding::{Decodable, Encodable};

use crate::module::registry::ModuleInstanceId;
use crate::module::ConsensusVersion;
use crate::transaction::Transaction;

/// All the items that may be produced during a consensus epoch
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub enum ConsensusItem {
    /// Threshold sign the epoch history for verification via the API
    Transaction(Transaction),
    /// Any data that modules require consensus on
    Module(ModuleConsensusItem),
    /// Vote to change consensus version of core or a module
    ConsensusVersionVote(ConsensusVersionVote),
    /// Allows us to add new items in the future without crashing old clients
    /// that try to interpret the session log.
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct ConsensusVersionVote {
    /// Module instance this vote is for. `None` means "core"
    pub module_id: Option<ModuleInstanceId>,
    /// Desired consensus version
    ///
    /// This lets the peer signal readiness to handle given consensus version.
    ///
    /// Notably once broadcasted, it can never be voted to lower value.
    pub desired: ConsensusVersion,
    /// Version desired to be enabled in a accelerated fashion (must be lower or
    /// equal `desired`).
    ///
    /// This lets the peer signal the will to accelerate enabling consensus
    /// version by waiting only for a threshold of peers supporting it, from
    /// the usual unanimity, up to and including this version.
    ///
    /// Must be lower or equal to `desired`.
    ///
    /// Notably once broadcasted, it can never be voted to lower value.
    pub accelerated: ConsensusVersion,
}

impl ConsensusVersionVote {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.accelerated <= self.desired,
            "Invalid consensus version vote: accelerated can't be higher than desired"
        );
        Ok(())
    }
}
