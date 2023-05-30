use std::time::Duration;

use fedimint_client::sm::{DynState, OperationId, State, StateTransition};
use fedimint_client::transaction::TxSubmissionError;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::ModuleDatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_dummy_common::DummyOutputOutcome;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::db::DummyClientFundsKeyV0;
use crate::{get_funds, DummyClientContext};

/// Tracks a transaction
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum DummyStateMachine {
    Input(Amount, TransactionId, OperationId),
    Output(Amount, TransactionId, OperationId),
    Done(Amount, OperationId),
}

impl State for DummyStateMachine {
    type ModuleContext = DummyClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match self.clone() {
            DummyStateMachine::Input(amount, txid, id) => vec![StateTransition::new(
                await_tx_accepted(global_context.clone(), id, txid),
                move |dbtx, res, _state: Self| match res {
                    // accepted, we are done
                    Ok(_) => Box::pin(async move { DummyStateMachine::Done(amount, id) }),
                    // tx rejected, we refund ourselves
                    Err(_) => Box::pin(add_funds(amount, dbtx.module_tx(), id)),
                },
            )],
            DummyStateMachine::Output(amount, txid, id) => vec![StateTransition::new(
                await_dummy_output_outcome(
                    global_context.clone(),
                    OutPoint { txid, out_idx: 0 },
                    context.dummy_decoder.clone(),
                ),
                move |dbtx, res, _state: Self| match res {
                    Ok(_) => Box::pin(async move { DummyStateMachine::Done(amount, id) }),
                    Err(_) => Box::pin(add_funds(amount, dbtx.module_tx(), id)),
                },
            )],
            DummyStateMachine::Done(_, _) => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            DummyStateMachine::Input(_, _, id) => *id,
            DummyStateMachine::Output(_, _, id) => *id,
            DummyStateMachine::Done(_, id) => *id,
        }
    }
}

async fn add_funds(
    amount: Amount,
    mut dbtx: ModuleDatabaseTransaction<'_>,
    id: OperationId,
) -> DummyStateMachine {
    let funds = get_funds(&mut dbtx).await + amount;
    dbtx.insert_entry(&DummyClientFundsKeyV0, &funds).await;
    DummyStateMachine::Done(amount, id)
}

// TODO: Boiler-plate, should return OutputOutcome
async fn await_tx_accepted(
    context: DynGlobalClientContext,
    id: OperationId,
    txid: TransactionId,
) -> Result<(), TxSubmissionError> {
    context.await_tx_accepted(id, txid).await
}

async fn await_dummy_output_outcome(
    global_context: DynGlobalClientContext,
    outpoint: OutPoint,
    module_decoder: Decoder,
) -> Result<(), DummyError> {
    global_context
        .api()
        .await_output_outcome::<DummyOutputOutcome>(
            outpoint,
            Duration::from_millis(i32::MAX as u64),
            &module_decoder,
        )
        .await
        .map_err(|_| DummyError::DummyInternalError)?;
    Ok(())
}

// TODO: Boiler-plate
impl IntoDynInstance for DummyStateMachine {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum DummyError {
    #[error("Dummy module had an internal error")]
    DummyInternalError,
}
