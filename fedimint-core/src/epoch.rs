use fedimint_core::core::{DynModuleConsensusItem as ModuleConsensusItem, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ModuleConsensusVersion;
use serde::{Deserialize, Serialize};

use crate::transaction::Transaction;

/// All the items that may be produced during a consensus epoch
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub enum ConsensusItem {
    /// Threshold sign the epoch history for verification via the API
    Transaction(Transaction),
    /// Any data that modules require consensus on
    Module(ModuleConsensusItem),
    /// A peer vote to activate a newer consensus version for a module.
    ModuleConsensusVersion(ModuleConsensusVersionVote),
    /// A peer vote for core consensus unix time.
    CoreUnixTime(ConsensusUnixTime),
    /// Allows us to add new items in the future without crashing old clients
    /// that try to interpret the session log.
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct ModuleConsensusVersionVote {
    pub module_instance_id: ModuleInstanceId,
    pub version: ModuleConsensusVersion,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ModuleConsensusVersionRequest {
    pub module_instance_id: ModuleInstanceId,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ActivateModuleConsensusVersionRequest {
    pub module_instance_id: ModuleInstanceId,
    pub version: Option<ModuleConsensusVersion>,
}

#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct ConsensusUnixTime(pub u64);
