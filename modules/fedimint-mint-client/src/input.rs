use std::sync::Arc;

use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{TieredMulti, TransactionId};
use fedimint_mint_common::MintInput;

use crate::{MintClientContext, MintClientStateMachines, SpendableNote};

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
        _context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            MintInputStates::Created(created) => created.transitions(&self.common, global_context),
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
    pub(crate) notes: TieredMulti<SpendableNote>,
}

impl MintInputStateCreated {
    fn transitions(
        &self,
        common: &MintInputCommon,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<MintInputStateMachine>> {
        let global_context = global_context.clone();
        vec![StateTransition::new(
            Self::await_success(*common, global_context.clone()),
            move |dbtx, result, old_state| {
                Box::pin(Self::transition_success(
                    result,
                    old_state,
                    dbtx,
                    global_context.clone(),
                ))
            },
        )]
    }

    async fn await_success(
        common: MintInputCommon,
        global_context: DynGlobalClientContext,
    ) -> Result<(), String> {
        global_context
            .await_tx_accepted(common.operation_id, common.txid)
            .await
    }

    async fn transition_success(
        result: Result<(), String>,
        old_state: MintInputStateMachine,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
    ) -> MintInputStateMachine {
        assert!(matches!(old_state.state, MintInputStates::Created(_)));

        match result {
            Ok(_) => {
                // Success case: containing transaction is accepted
                MintInputStateMachine {
                    common: old_state.common,
                    state: MintInputStates::Success(MintInputStateSuccess {}),
                }
            }
            Err(_) => {
                // Transaction rejected: attempting to refund
                Self::refund(dbtx, old_state, global_context).await
            }
        }
    }

    async fn refund(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: MintInputStateMachine,
        global_context: DynGlobalClientContext,
    ) -> MintInputStateMachine {
        let notes = match old_state.state {
            MintInputStates::Created(created) => created.notes,
            _ => panic!("Invalid state transition"),
        };

        let (spend_keys, snotes): (Vec<_>, TieredMulti<_>) = notes
            .into_iter_items()
            .map(|(amt, snote)| (snote.spend_key, (amt, snote.note())))
            .unzip();

        let refund_input = ClientInput::<MintInput, MintClientStateMachines> {
            input: MintInput(snotes),
            keys: spend_keys,
            // The input of the refund tx is managed by this state machine, so no new state machines
            // need to be created
            state_machines: Arc::new(|_, _| vec![]),
        };

        let (refund_txid, _) = global_context.claim_input(dbtx, refund_input).await;

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
        vec![StateTransition::new(
            Self::await_refund_success(*common, global_context.clone(), self.refund_txid),
            |_dbtx, result, old_state| Box::pin(Self::transition_refund_success(result, old_state)),
        )]
    }

    async fn await_refund_success(
        common: MintInputCommon,
        global_context: DynGlobalClientContext,
        refund_txid: TransactionId,
    ) -> Result<(), String> {
        global_context
            .await_tx_accepted(common.operation_id, refund_txid)
            .await
    }

    async fn transition_refund_success(
        result: Result<(), String>,
        old_state: MintInputStateMachine,
    ) -> MintInputStateMachine {
        let refund_txid = match old_state.state {
            MintInputStates::Refund(refund) => refund.refund_txid,
            _ => panic!("Invalid state transition"),
        };

        match result {
            Ok(_) => {
                // Refund successful
                MintInputStateMachine {
                    common: old_state.common,
                    state: MintInputStates::RefundSuccess(MintInputStateRefundSuccess {
                        refund_txid,
                    }),
                }
            }
            Err(_) => {
                // Refund failed
                // TODO: include e-cash notes for recovery? Although, they are in the log …
                MintInputStateMachine {
                    common: old_state.common,
                    state: MintInputStates::Error(MintInputStateError {
                        error: format!("Refund transaction {refund_txid} was rejected"),
                    }),
                }
            }
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
