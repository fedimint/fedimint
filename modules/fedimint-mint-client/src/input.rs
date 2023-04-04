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
pub enum MintInputStates {
    Created(MintInputStateCreated),
    Refund(MintInputStateRefund),
    Success(MintInputStateSuccess),
    Error(MintInputStateError),
    RefundSuccess(MintInputStateRefundSuccess),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintInputCommon {
    pub(crate) operation_id: OperationId,
    pub(crate) txid: TransactionId,
    pub(crate) input_idx: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintInputStateMachine {
    pub(crate) common: MintInputCommon,
    pub(crate) state: MintInputStates,
}

impl State for MintInputStateMachine {
    type ModuleContext = MintClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            MintInputStates::Created(created) => {
                created.transitions(&self.common, context, global_context)
            }
            MintInputStates::Refund(refund) => refund.transitions(&self.common, global_context),
            MintInputStates::Success(_) => {
                vec![]
            }
            MintInputStates::Error(_) => {
                vec![]
            }
            MintInputStates::RefundSuccess(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintInputStateCreated {
    notes: TieredMulti<SpendableNote>,
}

impl MintInputStateCreated {
    fn transitions(
        &self,
        common: &MintInputCommon,
        context: &MintClientContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<MintInputStateMachine>> {
        let rejected_context = context.clone();
        let rejected_global_context = global_context.clone();
        vec![
            // Success case: containing transaction is accepted
            StateTransition::new(
                Self::await_success(*common, global_context.clone()),
                |_dbtx, (), old_state| Box::pin(Self::transition_success(old_state)),
            ),
            // Transaction rejected: attempting to refund
            StateTransition::new(
                Self::await_refund(*common, global_context.clone()),
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

    async fn await_success(common: MintInputCommon, global_context: DynGlobalClientContext) {
        global_context
            .await_tx_accepted(common.operation_id, common.txid)
            .await;
    }

    async fn transition_success(old_state: MintInputStateMachine) -> MintInputStateMachine {
        assert!(matches!(old_state.state, MintInputStates::Created(_)));

        MintInputStateMachine {
            common: old_state.common,
            state: MintInputStates::Success(MintInputStateSuccess {}),
        }
    }

    async fn await_refund(common: MintInputCommon, global_context: DynGlobalClientContext) {
        global_context
            .await_tx_rejected(common.operation_id, common.txid)
            .await;
    }

    async fn transition_refund(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: MintInputStateMachine,
        context: MintClientContext,
        global_context: DynGlobalClientContext,
    ) -> MintInputStateMachine {
        let notes = match old_state.state {
            MintInputStates::Created(created) => created.notes,
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
                return MintInputStateMachine {
                    common: old_state.common,
                    state: MintInputStates::Error(MintInputStateError {
                        error: format!("Failed to create refund transaction: {e}"),
                    }),
                }
            }
        };

        MintInputStateMachine {
            common: old_state.common,
            state: MintInputStates::Refund(MintInputStateRefund { refund_txid }),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintInputStateRefund {
    refund_txid: TransactionId,
}

impl MintInputStateRefund {
    fn transitions(
        &self,
        common: &MintInputCommon,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<MintInputStateMachine>> {
        vec![
            // Refund successful
            StateTransition::new(
                Self::await_refund_success(*common, global_context.clone(), self.refund_txid),
                |_dbtx, (), old_state| Box::pin(Self::transition_refund_success(old_state)),
            ),
            // Refund failed
            StateTransition::new(
                Self::await_refund_failed(*common, global_context.clone(), self.refund_txid),
                |_dbtx, (), old_state| Box::pin(Self::transition_refund_failed(old_state)),
            ),
        ]
    }

    async fn await_refund_success(
        common: MintInputCommon,
        global_context: DynGlobalClientContext,
        refund_txid: TransactionId,
    ) {
        global_context
            .await_tx_accepted(common.operation_id, refund_txid)
            .await;
    }

    async fn transition_refund_success(old_state: MintInputStateMachine) -> MintInputStateMachine {
        let refund_txid = match old_state.state {
            MintInputStates::Refund(refund) => refund.refund_txid,
            _ => panic!("Invalid state transition"),
        };

        MintInputStateMachine {
            common: old_state.common,
            state: MintInputStates::RefundSuccess(MintInputStateRefundSuccess { refund_txid }),
        }
    }
    async fn await_refund_failed(
        common: MintInputCommon,
        global_context: DynGlobalClientContext,
        refund_txid: TransactionId,
    ) {
        global_context
            .await_tx_rejected(common.operation_id, refund_txid)
            .await;
    }

    async fn transition_refund_failed(old_state: MintInputStateMachine) -> MintInputStateMachine {
        let refund_txid = match old_state.state {
            MintInputStates::Refund(refund) => refund.refund_txid,
            _ => panic!("Invalid state transition"),
        };

        // TODO: include e-cash notes for recovery? Although, they are in the log …
        MintInputStateMachine {
            common: old_state.common,
            state: MintInputStates::Error(MintInputStateError {
                error: format!("Refund transaction {refund_txid} was rejected"),
            }),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintInputStateSuccess {}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintInputStateError {
    error: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintInputStateRefundSuccess {
    refund_txid: TransactionId,
}
