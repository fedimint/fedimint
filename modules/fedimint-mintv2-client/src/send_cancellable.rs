use std::time::SystemTime;

use fedimint_client::DynGlobalClientContext;
use fedimint_client::transaction::{ClientInput, ClientInputBundle};
use fedimint_client_module::module::OutPointRange;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_core::{runtime, time};
use fedimint_mintv2_common::MintInput;

use crate::{MintClientContext, SpendableNote};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SendCancellableStateMachine {
    pub common: SendCancellableSMCommon,
    pub state: SendCancellableSMState,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SendCancellableSMCommon {
    pub operation_id: OperationId,
    pub spendable_notes: Vec<SpendableNote>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum SendCancellableSMState {
    Created(SendCancellableSMCreated),
    UserRefund(SendCancellableSMRefund),
    TimeoutRefund(SendCancellableSMRefund),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SendCancellableSMCreated {
    pub timeout: SystemTime,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SendCancellableSMRefund {
    pub refund_range: OutPointRange,
}

impl State for SendCancellableStateMachine {
    type ModuleContext = MintClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let SendCancellableSMState::Created(created) = &self.state else {
            return vec![];
        };

        let manual_cancel_context = context.clone();
        let manual_cancel_gc = global_context.clone();
        let timeout_context = context.clone();
        let timeout_gc = global_context.clone();

        vec![
            StateTransition::new(
                context.await_cancel_send(self.common.operation_id),
                move |dbtx, (), old_state| {
                    Box::pin(Self::transition_cancel(
                        dbtx,
                        old_state,
                        manual_cancel_context.clone(),
                        manual_cancel_gc.clone(),
                        true,
                    ))
                },
            ),
            StateTransition::new(
                await_timeout_cancel(created.timeout),
                move |dbtx, (), old_state| {
                    Box::pin(Self::transition_cancel(
                        dbtx,
                        old_state,
                        timeout_context.clone(),
                        timeout_gc.clone(),
                        false,
                    ))
                },
            ),
        ]
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl SendCancellableStateMachine {
    async fn transition_cancel(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: SendCancellableStateMachine,
        context: MintClientContext,
        global_context: DynGlobalClientContext,
        user_triggered: bool,
    ) -> SendCancellableStateMachine {
        let refund_range =
            reclaim_sent_notes(dbtx, old_state.common.clone(), context, global_context).await;

        let state = if user_triggered {
            SendCancellableSMState::UserRefund(SendCancellableSMRefund { refund_range })
        } else {
            SendCancellableSMState::TimeoutRefund(SendCancellableSMRefund { refund_range })
        };

        SendCancellableStateMachine {
            common: old_state.common,
            state,
        }
    }
}

async fn await_timeout_cancel(deadline: SystemTime) {
    if let Ok(time_until_deadline) = deadline.duration_since(time::now()) {
        runtime::sleep(time_until_deadline).await;
    }
}

async fn reclaim_sent_notes(
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    common: SendCancellableSMCommon,
    context: MintClientContext,
    global_context: DynGlobalClientContext,
) -> OutPointRange {
    let amount_unit = context.amount_unit;
    let inputs = common
        .spendable_notes
        .iter()
        .map(|spendable_note| ClientInput::<MintInput> {
            input: MintInput::new_v0(spendable_note.note()),
            keys: vec![spendable_note.keypair],
            amounts: Amounts::new_custom(amount_unit, spendable_note.amount()),
        })
        .collect();

    global_context
        .claim_inputs(dbtx, ClientInputBundle::new_no_sm(inputs))
        .await
        .expect("Cannot claim input, additional funding needed")
}
