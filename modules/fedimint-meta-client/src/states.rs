use fedimint_client::sm::{DynState, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::MetaClientContext;

/// Tracks a transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum MetaStateMachine {}

impl State for MetaStateMachine {
    type ModuleContext = MetaClientContext;

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
impl IntoDynInstance for MetaStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum MetaError {
    #[error("Meta module had an internal error")]
    MetaInternalError,
}
