use std::sync::Arc;
use std::time::SystemTime;

use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{task, TieredMulti, TransactionId};
use fedimint_mint_common::MintInput;

use crate::input::{
    MintInputCommon, MintInputStateCreated, MintInputStateMachine, MintInputStates,
};
use crate::{MintClientContext, MintClientStateMachines, SpendableNote};

#[aquamarine::aquamarine]
/// State machine managing e-cash that has been taken out of the wallet for
/// out-of-band transmission.
///
/// ```mermaid
/// graph LR
///     Created -- User triggered refund --> RefundU["User Refund"]
///     Created -- Timeout triggered refund --> RefundT["Timeout Refund"]
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum MintOOBStates {
    /// The e-cash has been taken out of the wallet and we are waiting for the
    /// recipient to reissue it or the user to trigger a refund.
    Created(MintOOBStatesCreated),
    /// The user has triggered a refund.
    UserRefund(MintOOBStatesUserRefund),
    /// The timeout of this out-of-band transaction was hit and we attempted to
    /// refund. This refund *failing* is the expected behavior since the
    /// recipient is supposed to have already reissued it.
    TimeoutRefund(MintOOBStatesTimeoutRefund),
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintOOBStateMachine {
    pub(crate) operation_id: OperationId,
    pub(crate) state: MintOOBStates,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintOOBStatesCreated {
    pub(crate) notes: TieredMulti<SpendableNote>,
    pub(crate) timeout: SystemTime,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintOOBStatesUserRefund {
    pub(crate) refund_txid: TransactionId,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintOOBStatesTimeoutRefund {
    pub(crate) refund_txid: TransactionId,
}

impl State for MintOOBStateMachine {
    type ModuleContext = MintClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            MintOOBStates::Created(created) => {
                created.transitions(self.operation_id, context, global_context)
            }
            MintOOBStates::UserRefund(_) => {
                vec![]
            }
            MintOOBStates::TimeoutRefund(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

impl MintOOBStatesCreated {
    fn transitions(
        &self,
        operation_id: OperationId,
        context: &MintClientContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<MintOOBStateMachine>> {
        // TODO: pass refund contexts into state transitions
        let user_cancel_gc = global_context.clone();
        let timeout_cancel_gc = global_context.clone();
        vec![
            StateTransition::new(
                await_user_cancels(operation_id, context.subscribe_cancel_oob_payment()),
                move |dbtx, (), state| {
                    Box::pin(transition_user_cancel(state, dbtx, user_cancel_gc.clone()))
                },
            ),
            StateTransition::new(
                await_timeout_cancel(self.timeout),
                move |dbtx, (), state| {
                    Box::pin(transition_timeout_cancel(
                        state,
                        dbtx,
                        timeout_cancel_gc.clone(),
                    ))
                },
            ),
        ]
    }
}

async fn await_user_cancels(
    operation_id: OperationId,
    mut oob_cancel_receiver: tokio::sync::broadcast::Receiver<OperationId>,
) {
    while let Ok(op) = oob_cancel_receiver.recv().await {
        if operation_id == op {
            return;
        }
    }
    std::future::pending().await
}

async fn transition_user_cancel(
    prev_state: MintOOBStateMachine,
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    global_context: DynGlobalClientContext,
) -> MintOOBStateMachine {
    let spendable_notes = match prev_state.state {
        MintOOBStates::Created(created) => created.notes,
        _ => panic!("Invalid previous state: {prev_state:?}"),
    };

    let refund_txid = try_cancel_oob_spend(
        dbtx,
        prev_state.operation_id,
        spendable_notes,
        global_context,
    )
    .await;
    MintOOBStateMachine {
        operation_id: prev_state.operation_id,
        state: MintOOBStates::UserRefund(MintOOBStatesUserRefund { refund_txid }),
    }
}

async fn await_timeout_cancel(deadline: SystemTime) {
    if let Ok(time_until_deadline) = deadline.duration_since(fedimint_core::time::now()) {
        task::sleep(time_until_deadline).await;
    }
}

async fn transition_timeout_cancel(
    prev_state: MintOOBStateMachine,
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    global_context: DynGlobalClientContext,
) -> MintOOBStateMachine {
    let spendable_notes = match prev_state.state {
        MintOOBStates::Created(created) => created.notes,
        _ => panic!("Invalid previous state: {prev_state:?}"),
    };

    let refund_txid = try_cancel_oob_spend(
        dbtx,
        prev_state.operation_id,
        spendable_notes,
        global_context,
    )
    .await;
    MintOOBStateMachine {
        operation_id: prev_state.operation_id,
        state: MintOOBStates::TimeoutRefund(MintOOBStatesTimeoutRefund { refund_txid }),
    }
}

async fn try_cancel_oob_spend(
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    operation_id: OperationId,
    spendable_notes: TieredMulti<SpendableNote>,
    global_context: DynGlobalClientContext,
) -> TransactionId {
    let (keys, snotes): (Vec<_>, TieredMulti<_>) = spendable_notes
        .iter_items()
        .map(|(amt, snote)| (snote.spend_key, (amt, snote.note())))
        .unzip();

    let input = ClientInput {
        input: MintInput(snotes),
        keys,
        state_machines: Arc::new(move |txid, input_idx| {
            vec![MintClientStateMachines::Input(MintInputStateMachine {
                common: MintInputCommon {
                    operation_id,
                    txid,
                    input_idx,
                },
                state: MintInputStates::Created(MintInputStateCreated {
                    notes: spendable_notes.clone(),
                }),
            })]
        }),
    };

    global_context.claim_input(dbtx, input).await.0
}
