#![allow(clippy::pedantic)]

use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{DynState, State, StateTransition};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};

use crate::DummyClientContext;

/// Empty state machine - dummy module doesn't use state machines
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum DummyStateMachine {}

impl State for DummyStateMachine {
    type ModuleContext = DummyClientContext;

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

impl IntoDynInstance for DummyStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}
