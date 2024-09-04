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
    /// Vote to change the effective consensus version of core or a module
    ConsensusVersionVote(ConsensusVersionVote),
    /// Allows us to add new items in the future without crashing old clients
    /// that try to interpret the session log.
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// Vote to change the effective consensus version of core or a module
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct ConsensusVersionVote {
    /// Module instance this vote is for. `None` means "core"
    pub module_id: Option<ModuleInstanceId>,
    /// Desired consensus version
    ///
    /// This lets the peer signal readiness to handle given consensus version.
    ///
    /// Notably once broadcasted, it can never be voted to a lower value.
    pub desired: ConsensusVersion,
    /// Vote for activating new versions in an accelerated fashion (without
    /// waiting for all peers to be ready, but only a threshold of them).
    ///
    /// Notably once set to true, it can't be unset until new vote (for higher
    /// version) is submitted.
    pub accelerate: bool,
}
