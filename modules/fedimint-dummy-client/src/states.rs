#![allow(clippy::pedantic)]

use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{DynState, State, StateTransition};
use fedimint_core::TransactionId;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};

use crate::DummyClientContext;

/// Tracks a transaction output
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum DummyStateMachine {
    Output(TransactionId, OperationId),
    OutputDone(TransactionId, OperationId),
    Refund(OperationId),
}

impl State for DummyStateMachine {
    type ModuleContext = DummyClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self.clone() {
            DummyStateMachine::Output(txid, id) => vec![StateTransition::new(
                await_tx_accepted(global_context.clone(), txid),
                move |_dbtx, res, _state: Self| match res {
                    Ok(()) => Box::pin(async move { DummyStateMachine::OutputDone(txid, id) }),
                    Err(_) => Box::pin(async move { DummyStateMachine::Refund(id) }),
                },
            )],
            DummyStateMachine::OutputDone(_, _) | DummyStateMachine::Refund(_) => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            DummyStateMachine::Output(_, id)
            | DummyStateMachine::OutputDone(_, id)
            | DummyStateMachine::Refund(id) => *id,
        }
    }
}

async fn await_tx_accepted(
    context: DynGlobalClientContext,
    txid: TransactionId,
) -> Result<(), String> {
    context.await_tx_accepted(txid).await
}

impl IntoDynInstance for DummyStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}
