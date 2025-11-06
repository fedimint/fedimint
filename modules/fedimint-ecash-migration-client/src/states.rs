use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{DynState, State, StateTransition};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::EcashMigrationClientContext;

/// Tracks a transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum EcashMigrationStateMachine {}

impl State for EcashMigrationStateMachine {
    type ModuleContext = EcashMigrationClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        unreachable!()
    }

    fn operation_id(&self) -> OperationId {
        unreachable!()
    }
}

// TODO: Boiler-plate
impl IntoDynInstance for EcashMigrationStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum EcashMigrationError {
    #[error("Ecash migration module had an internal error")]
    EcashMigrationInternalError,
}
