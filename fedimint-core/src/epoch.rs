use fedimint_core::core::DynModuleConsensusItem as ModuleConsensusItem;
use fedimint_core::encoding::{Decodable, Encodable};

use crate::transaction::Transaction;

/// All the items that may be produced during a consensus epoch
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub enum ConsensusItem {
    /// Threshold sign the epoch history for verification via the API
    Transaction(Transaction),
    /// Any data that modules require consensus on
    Module(ModuleConsensusItem),
}
