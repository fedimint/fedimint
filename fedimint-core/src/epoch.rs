use fedimint_core::core::DynModuleConsensusItem as ModuleConsensusItem;
use fedimint_core::encoding::{Decodable, Encodable};

use crate::module::registry::ModuleInstanceId;
use crate::module::{CoreConsensusVersion, ModuleConsensusVersion};
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
pub enum ConsensusVersionVote {
    Core(CoreConsensusVersion),
    Module {
        id: ModuleInstanceId,
        version: ModuleConsensusVersion,
    },
}
