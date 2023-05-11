use fedimint_client::sm::{DynState, OperationId, State, StateTransition};
use fedimint_client::transaction::TxSubmissionError;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::ModuleDatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, TransactionId};

use crate::db::DummyClientFundsKeyV0;
use crate::{get_funds, DummyClientContext};

/// Tracks a transaction
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum DummyStateMachine {
    Input(Amount, TransactionId, OperationId),
    Output(Amount, TransactionId, OperationId),
    Done,
}

impl State for DummyStateMachine {
    type ModuleContext = DummyClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match self.clone() {
            DummyStateMachine::Input(amount, txid, id) => vec![StateTransition::new(
                await_tx_accepted(global_context.clone(), id, txid),
                move |dbtx, res, _state: Self| match res {
                    // accepted, we are done
                    Ok(_) => Box::pin(async { DummyStateMachine::Done }),
                    // tx rejected, we refund ourselves
                    Err(_) => Box::pin(add_funds(amount, dbtx.module_tx())),
                },
            )],
            DummyStateMachine::Output(amount, txid, id) => vec![StateTransition::new(
                await_tx_accepted(global_context.clone(), id, txid),
                move |dbtx, res, _state: Self| match res {
                    // rejected, we don't get any funds
                    Ok(_) => Box::pin(async { DummyStateMachine::Done }),
                    // tx accepted, add to our funds
                    Err(_) => Box::pin(add_funds(amount, dbtx.module_tx())),
                },
            )],
            DummyStateMachine::Done => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            DummyStateMachine::Input(_, _, id) => *id,
            DummyStateMachine::Output(_, _, id) => *id,
            DummyStateMachine::Done => [0; 32],
        }
    }
}

async fn add_funds(amount: Amount, mut dbtx: ModuleDatabaseTransaction<'_>) -> DummyStateMachine {
    let funds = get_funds(&mut dbtx).await + amount;
    dbtx.insert_entry(&DummyClientFundsKeyV0, &funds).await;
    DummyStateMachine::Done
}

// TODO: Boiler-plate, should return OutputOutcome
async fn await_tx_accepted(
    context: DynGlobalClientContext,
    id: OperationId,
    txid: TransactionId,
) -> Result<(), TxSubmissionError> {
    context.await_tx_accepted(id, txid).await
}

// TODO: Boiler-plate
impl IntoDynInstance for DummyStateMachine {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}
