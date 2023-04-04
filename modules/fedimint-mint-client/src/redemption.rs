use fedimint_client::sm::{ClientSMDatabaseTransaction, OperationId, State, StateTransition};
use fedimint_client::transaction::{ClientInput, TransactionBuilder};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::DynInput;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{TieredMulti, TransactionId};
use fedimint_mint_common::MintInput;

use crate::{MintClientContext, SpendableNote};

// TODO: add retry with valid subset of e-cash notes
/// State machine managing the e-cash redemption process related to a mint
/// input.
///
/// ```mermaid
/// graph LR
///     classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     Created -- containing tx accepted --> Success
///     Created -- containing tx rejected --> Refund
///     Refund -- refund tx rejected --> Error
///     Refund -- refund tx accepted --> RS[Refund Success]
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum MintRedemptionStates {
    Created(MintRedemptionStateCreated),
    Refund(MintRedemptionStateRefund),
    Success(MintRedemptionStateSuccess),
    Error(MintRedemptionStateError),
    RefundSuccess(MintRedemptionStateRefundSuccess),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintRedemptionCommon {
    pub(crate) operation_id: OperationId,
    pub(crate) txid: TransactionId,
    pub(crate) input_idx: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintRedemptionStateMachine {
    pub(crate) common: MintRedemptionCommon,
    pub(crate) state: MintRedemptionStates,
}

impl State for MintRedemptionStateMachine {
    type ModuleContext = MintClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            MintRedemptionStates::Created(created) => {
                created.transitions(&self.common, context, global_context)
            }
            MintRedemptionStates::Refund(refund) => {
                refund.transitions(&self.common, global_context)
            }
            MintRedemptionStates::Success(_) => {
                vec![]
            }
            MintRedemptionStates::Error(_) => {
                vec![]
            }
            MintRedemptionStates::RefundSuccess(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintRedemptionStateCreated {
    notes: TieredMulti<SpendableNote>,
}

impl MintRedemptionStateCreated {
    fn transitions(
        &self,
        common: &MintRedemptionCommon,
        context: &MintClientContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<MintRedemptionStateMachine>> {
        let rejected_context = context.clone();
        let rejected_global_context = global_context.clone();
        vec![
            // Success case: containing transaction is accepted
            StateTransition::new(
                Self::trigger_success(*common, global_context.clone()),
                |_dbtx, (), old_state| Box::pin(Self::transition_success(old_state)),
            ),
            // Transaction rejected: attempting to refund
            StateTransition::new(
                Self::trigger_refund(*common, global_context.clone()),
                move |dbtx, (), old_state| {
                    Box::pin(Self::transition_refund(
                        dbtx,
                        old_state,
                        rejected_context.clone(),
                        rejected_global_context.clone(),
                    ))
                },
            ),
        ]
    }

    async fn trigger_success(common: MintRedemptionCommon, global_context: DynGlobalClientContext) {
        global_context
            .await_tx_accepted(common.operation_id, common.txid)
            .await;
    }

    async fn transition_success(
        old_state: MintRedemptionStateMachine,
    ) -> MintRedemptionStateMachine {
        assert!(matches!(old_state.state, MintRedemptionStates::Created(_)));

        MintRedemptionStateMachine {
            common: old_state.common,
            state: MintRedemptionStates::Success(MintRedemptionStateSuccess {}),
        }
    }

    async fn trigger_refund(common: MintRedemptionCommon, global_context: DynGlobalClientContext) {
        global_context
            .await_tx_rejected(common.operation_id, common.txid)
            .await;
    }

    async fn transition_refund(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: MintRedemptionStateMachine,
        context: MintClientContext,
        global_context: DynGlobalClientContext,
    ) -> MintRedemptionStateMachine {
        let notes = match old_state.state {
            MintRedemptionStates::Created(created) => created.notes,
            _ => panic!("Invalid state transition"),
        };

        let (spend_keys, notes): (Vec<_>, TieredMulti<_>) = notes
            .into_iter_items()
            .map(|(amt, note)| (note.spend_key, (amt, note.note)))
            .unzip();

        let refund_input = ClientInput {
            input: DynInput::from_typed(context.instance_id, MintInput(notes)),
            keys: spend_keys,
            // The refund tx is managed by this state machine, so no new state machines need to be
            // created
            state_machines: Box::new(|_, _| vec![]),
        };

        let mut transaction_builder = TransactionBuilder::new();
        transaction_builder.with_input(refund_input);

        let refund_txid = match global_context
            .finalize_and_submit_transaction(
                dbtx,
                old_state.common.operation_id,
                transaction_builder,
            )
            .await
        {
            Ok(refund_txid) => refund_txid,
            Err(e) => {
                return MintRedemptionStateMachine {
                    common: old_state.common,
                    state: MintRedemptionStates::Error(MintRedemptionStateError {
                        error: format!("Failed to create refund transaction: {e}"),
                    }),
                }
            }
        };

        MintRedemptionStateMachine {
            common: old_state.common,
            state: MintRedemptionStates::Refund(MintRedemptionStateRefund { refund_txid }),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintRedemptionStateRefund {
    refund_txid: TransactionId,
}

impl MintRedemptionStateRefund {
    fn transitions(
        &self,
        common: &MintRedemptionCommon,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<MintRedemptionStateMachine>> {
        vec![
            // Refund successful
            StateTransition::new(
                Self::trigger_refund_success(*common, global_context.clone(), self.refund_txid),
                |_dbtx, (), old_state| Box::pin(Self::transition_refund_success(old_state)),
            ),
            // Refund failed
            StateTransition::new(
                Self::trigger_refund_failed(*common, global_context.clone(), self.refund_txid),
                |_dbtx, (), old_state| Box::pin(Self::transition_refund_failed(old_state)),
            ),
        ]
    }

    async fn trigger_refund_success(
        common: MintRedemptionCommon,
        global_context: DynGlobalClientContext,
        refund_txid: TransactionId,
    ) {
        global_context
            .await_tx_accepted(common.operation_id, refund_txid)
            .await;
    }

    async fn transition_refund_success(
        old_state: MintRedemptionStateMachine,
    ) -> MintRedemptionStateMachine {
        let refund_txid = match old_state.state {
            MintRedemptionStates::Refund(refund) => refund.refund_txid,
            _ => panic!("Invalid state transition"),
        };

        MintRedemptionStateMachine {
            common: old_state.common,
            state: MintRedemptionStates::RefundSuccess(MintRedemptionStateRefundSuccess {
                refund_txid,
            }),
        }
    }
    async fn trigger_refund_failed(
        common: MintRedemptionCommon,
        global_contex: DynGlobalClientContext,
        refund_txid: TransactionId,
    ) {
        global_contex
            .await_tx_rejected(common.operation_id, refund_txid)
            .await;
    }

    async fn transition_refund_failed(
        old_state: MintRedemptionStateMachine,
    ) -> MintRedemptionStateMachine {
        let refund_txid = match old_state.state {
            MintRedemptionStates::Refund(refund) => refund.refund_txid,
            _ => panic!("Invalid state transition"),
        };

        // TODO: include e-cash notes for recovery? Although, they are in the log …
        MintRedemptionStateMachine {
            common: old_state.common,
            state: MintRedemptionStates::Error(MintRedemptionStateError {
                error: format!("Refund transaction {refund_txid} was rejected"),
            }),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintRedemptionStateSuccess {}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintRedemptionStateError {
    error: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintRedemptionStateRefundSuccess {
    refund_txid: TransactionId,
}
