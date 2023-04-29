use fedimint_client::DynGlobalClientContext;
use fedimint_client::sm::{ClientSMDatabaseTransaction, DynState, OperationId, State, StateTransition};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, TransactionId};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use crate::DummyClientContext;

/// Tracks a state of a tx until done
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct DummyClientStateMachine {
    pub operation_id: OperationId,
    pub txid: TransactionId,
    pub idx: u64,
    pub amount: Amount,
    pub state: DummyClientState,
}

impl DummyClientStateMachine {
    async fn add_amount(self, dbtx: &mut ClientSMDatabaseTransaction<'_, '_>) -> Self {
        let funds = crate::get_funds(&mut dbtx.module_tx()).await;
        crate::set_funds(&mut dbtx.module_tx(), funds + self.amount).await;
        self.done().await
    }

    async fn done(self) -> Self {
        let mut state_machine = self;
        state_machine.state = DummyClientState::Done;
        state_machine
    }
}

/// Possible states for a tx
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum DummyClientState {
    Input,
    Output,
    Done,
}

impl State for DummyClientStateMachine {
    type ModuleContext = DummyClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match self.state {
            DummyClientState::Input => vec![StateTransition::new(
                await_tx_accepted(global_context.clone(), self.operation_id, self.txid),
                |dbtx, res, state: Self| match res {
                    // input accepted, we are done
                    Ok(_) => Box::pin(state.done()),
                    // input rejected, add back our funds
                    Err(_) => Box::pin(state.add_amount(dbtx)),
                },
            )],
            DummyClientState::Output => vec![StateTransition::new(
                await_tx_accepted(global_context.clone(), self.operation_id, self.txid),
                |dbtx, res, state: Self| match res {
                    // output accepted, add to our funds
                    Ok(_) => Box::pin(state.add_amount(dbtx)),
                    // output rejected, we are done
                    Err(_) => Box::pin(state.done()),
                },
            )],
            DummyClientState::Done => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

// TODO: Boiler-plate
async fn await_tx_accepted(
    context: DynGlobalClientContext,
    id: OperationId,
    txid: TransactionId,
) -> Result<(), ()> {
    context.clone().await_tx_accepted(id, txid).await
}

// TODO: Boiler-plate
impl IntoDynInstance for DummyClientStateMachine {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}
