use std::sync::Arc;
use std::time::SystemTime;

use fedimint_client::module::OutPointRange;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientInputBundle, ClientInputSM};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{runtime, Amount, TransactionId};
use fedimint_mint_common::MintInput;

use crate::input::{
    MintInputCommon, MintInputStateMachine, MintInputStateRefundedBundle, MintInputStates,
};
use crate::{MintClientContext, MintClientStateMachines, SpendableNote};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum MintOOBStatesV0 {
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

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine managing e-cash that has been taken out of the wallet for
/// out-of-band transmission.
///
/// ```mermaid
/// graph LR
///     Created -- User triggered refund --> RefundU["User Refund"]
///     Created -- Timeout triggered refund --> RefundT["Timeout Refund"]
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum MintOOBStates {
    /// The e-cash has been taken out of the wallet and we are waiting for the
    /// recipient to reissue it or the user to trigger a refund.
    CreatedMulti(MintOOBStatesCreatedMulti),
    /// The user has triggered a refund.
    UserRefundMulti(MintOOBStatesUserRefundMulti),
    /// The timeout of this out-of-band transaction was hit and we attempted to
    /// refund. This refund *failing* is the expected behavior since the
    /// recipient is supposed to have already reissued it.
    TimeoutRefund(MintOOBStatesTimeoutRefund),

    // States we want to drop eventually (that's why they are last)
    // -
    /// Obsoleted, legacy from [`MintOOBStatesV0`], like
    /// [`MintOOBStates::CreatedMulti`] but for a single note only.
    Created(MintOOBStatesCreated),
    /// Obsoleted, legacy from [`MintOOBStatesV0`], like
    /// [`MintOOBStates::UserRefundMulti`] but for single note only
    UserRefund(MintOOBStatesUserRefund),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOOBStateMachineV0 {
    pub(crate) operation_id: OperationId,
    pub(crate) state: MintOOBStatesV0,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOOBStateMachine {
    pub(crate) operation_id: OperationId,
    pub(crate) state: MintOOBStates,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOOBStatesCreated {
    pub(crate) amount: Amount,
    pub(crate) spendable_note: SpendableNote,
    pub(crate) timeout: SystemTime,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOOBStatesCreatedMulti {
    pub(crate) spendable_notes: Vec<(Amount, SpendableNote)>,
    pub(crate) timeout: SystemTime,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOOBStatesUserRefundMulti {
    /// The txid we are hoping succeeds refunding all notes in one go
    pub(crate) refund_txid: TransactionId,
    /// The notes we are going to refund individually if it doesn't
    pub(crate) spendable_notes: Vec<(Amount, SpendableNote)>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOOBStatesUserRefund {
    pub(crate) refund_txid: TransactionId,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOOBStatesTimeoutRefund {
    pub(crate) refund_txid: TransactionId,
}

impl State for MintOOBStateMachine {
    type ModuleContext = MintClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            MintOOBStates::Created(created) => {
                created.transitions(self.operation_id, context, global_context)
            }
            MintOOBStates::CreatedMulti(created) => {
                created.transitions(self.operation_id, context, global_context)
            }
            MintOOBStates::UserRefund(_)
            | MintOOBStates::TimeoutRefund(_)
            | MintOOBStates::UserRefundMulti(_) => {
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
        let user_cancel_gc = global_context.clone();
        let timeout_cancel_gc = global_context.clone();
        vec![
            StateTransition::new(
                context.await_cancel_oob_payment(operation_id),
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

impl MintOOBStatesCreatedMulti {
    fn transitions(
        &self,
        operation_id: OperationId,
        context: &MintClientContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<MintOOBStateMachine>> {
        let user_cancel_gc = global_context.clone();
        let timeout_cancel_gc = global_context.clone();
        vec![
            StateTransition::new(
                context.await_cancel_oob_payment(operation_id),
                move |dbtx, (), state| {
                    Box::pin(transition_user_cancel_multi(
                        state,
                        dbtx,
                        user_cancel_gc.clone(),
                    ))
                },
            ),
            StateTransition::new(
                await_timeout_cancel(self.timeout),
                move |dbtx, (), state| {
                    Box::pin(transition_timeout_cancel_multi(
                        state,
                        dbtx,
                        timeout_cancel_gc.clone(),
                    ))
                },
            ),
        ]
    }
}

async fn transition_user_cancel(
    prev_state: MintOOBStateMachine,
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    global_context: DynGlobalClientContext,
) -> MintOOBStateMachine {
    let (amount, spendable_note) = match prev_state.state {
        MintOOBStates::Created(created) => (created.amount, created.spendable_note),
        _ => panic!("Invalid previous state: {prev_state:?}"),
    };

    let refund_txid = try_cancel_oob_spend(
        dbtx,
        prev_state.operation_id,
        amount,
        spendable_note,
        global_context,
    )
    .await;
    MintOOBStateMachine {
        operation_id: prev_state.operation_id,
        state: MintOOBStates::UserRefund(MintOOBStatesUserRefund { refund_txid }),
    }
}

async fn transition_user_cancel_multi(
    prev_state: MintOOBStateMachine,
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    global_context: DynGlobalClientContext,
) -> MintOOBStateMachine {
    let spendable_notes = match prev_state.state {
        MintOOBStates::CreatedMulti(created) => created.spendable_notes,
        _ => panic!("Invalid previous state: {prev_state:?}"),
    };

    let refund_txid = try_cancel_oob_spend_multi(
        dbtx,
        prev_state.operation_id,
        spendable_notes.clone(),
        global_context,
    )
    .await;
    MintOOBStateMachine {
        operation_id: prev_state.operation_id,
        state: MintOOBStates::UserRefundMulti(MintOOBStatesUserRefundMulti {
            refund_txid,
            spendable_notes,
        }),
    }
}

async fn await_timeout_cancel(deadline: SystemTime) {
    if let Ok(time_until_deadline) = deadline.duration_since(fedimint_core::time::now()) {
        runtime::sleep(time_until_deadline).await;
    }
}

async fn transition_timeout_cancel(
    prev_state: MintOOBStateMachine,
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    global_context: DynGlobalClientContext,
) -> MintOOBStateMachine {
    let (amount, spendable_note) = match prev_state.state {
        MintOOBStates::Created(created) => (created.amount, created.spendable_note),
        _ => panic!("Invalid previous state: {prev_state:?}"),
    };

    let refund_txid = try_cancel_oob_spend(
        dbtx,
        prev_state.operation_id,
        amount,
        spendable_note,
        global_context,
    )
    .await;
    MintOOBStateMachine {
        operation_id: prev_state.operation_id,
        state: MintOOBStates::TimeoutRefund(MintOOBStatesTimeoutRefund { refund_txid }),
    }
}

async fn transition_timeout_cancel_multi(
    prev_state: MintOOBStateMachine,
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    global_context: DynGlobalClientContext,
) -> MintOOBStateMachine {
    let spendable_notes = match prev_state.state {
        MintOOBStates::CreatedMulti(created) => created.spendable_notes,
        _ => panic!("Invalid previous state: {prev_state:?}"),
    };

    let refund_txid = try_cancel_oob_spend_multi(
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
    amount: Amount,
    spendable_note: SpendableNote,
    global_context: DynGlobalClientContext,
) -> TransactionId {
    try_cancel_oob_spend_multi(
        dbtx,
        operation_id,
        vec![(amount, spendable_note)],
        global_context,
    )
    .await
}

async fn try_cancel_oob_spend_multi(
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    operation_id: OperationId,
    spendable_notes: Vec<(Amount, SpendableNote)>,
    global_context: DynGlobalClientContext,
) -> TransactionId {
    let inputs = spendable_notes
        .clone()
        .into_iter()
        .map(|(amount, spendable_note)| ClientInput {
            input: MintInput::new_v0(amount, spendable_note.note()),
            keys: vec![spendable_note.spend_key],
            amount,
        })
        .collect();

    let sm = ClientInputSM {
        state_machines: Arc::new(move |out_point_range: OutPointRange| {
            debug_assert_eq!(out_point_range.count(), spendable_notes.len());
            vec![MintClientStateMachines::Input(MintInputStateMachine {
                common: MintInputCommon {
                    operation_id,
                    out_point_range,
                },
                // When canceling OOB, we are reating the multi-refund input already here.
                // So  we can cut straight to
                // `MintInputStates::RefundedMulti` state. If the reund tx fails, it will
                // retry using per-note refund again.
                state: MintInputStates::RefundedBundle(MintInputStateRefundedBundle {
                    refund_txid: out_point_range.txid(),
                    spendable_notes: spendable_notes.clone(),
                }),
            })]
        }),
    };

    global_context
        .claim_inputs(dbtx, ClientInputBundle::new(inputs, vec![sm]))
        .await
        .expect("Cannot claim input, additional funding needed")
        .0
}
