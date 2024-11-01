use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientInputBundle};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, TransactionId};
use fedimint_logging::LOG_CLIENT_MODULE_MINT;
use fedimint_mint_common::MintInput;
use tracing::{debug, warn};

use crate::{MintClientContext, SpendableNote};

#[cfg_attr(doc, aquamarine::aquamarine)]
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
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum MintInputStates {
    #[deprecated(note = "Use CreateMulti instead")]
    Created(MintInputStateCreated),
    Refund(MintInputStateRefund),
    Success(MintInputStateSuccess),
    Error(MintInputStateError),
    RefundSuccess(MintInputStateRefundSuccess),
    /// Like [`Self::Created`], but tracks multiple notes at the same time
    CreatedMulti(MintInputStateCreatedMulti),
    /// Refund multiple notes in one tx, if fails, switch to per-note
    /// [`Self::Refund`]
    RefundMulti(MintInputStateRefundMulti),
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Decodable, Encodable)]
pub struct MintInputCommonV1 {
    pub(crate) operation_id: OperationId,
    pub(crate) txid: TransactionId,
    pub(crate) input_idx: u64,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Decodable, Encodable)]
pub struct MintInputCommon {
    pub(crate) operation_id: OperationId,
    pub(crate) txid: TransactionId,
    pub(crate) input_idxs: std::ops::RangeInclusive<u64>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintInputStateMachineV1 {
    pub(crate) common: MintInputCommonV1,
    pub(crate) state: MintInputStates,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintInputStateMachine {
    pub(crate) common: MintInputCommon,
    pub(crate) state: MintInputStates,
}

impl State for MintInputStateMachine {
    type ModuleContext = MintClientContext;

    #[allow(deprecated)]
    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            MintInputStates::Created(_) => {
                MintInputStateCreated::transitions(&self.common, global_context)
            }
            MintInputStates::CreatedMulti(_) => {
                MintInputStateCreatedMulti::transitions(&self.common, global_context)
            }
            MintInputStates::Refund(refund) => refund.transitions(global_context),
            MintInputStates::Success(_)
            | MintInputStates::Error(_)
            | MintInputStates::RefundSuccess(_)
            // `RefundMulti` means that the refund was split between multiple new per-note state machines, so
            // the current state machine has nothing more to do
            | MintInputStates::RefundMulti(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintInputStateCreated {
    pub(crate) amount: Amount,
    pub(crate) spendable_note: SpendableNote,
}

impl MintInputStateCreated {
    fn transitions(
        common: &MintInputCommon,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<MintInputStateMachine>> {
        let global_context = global_context.clone();
        vec![StateTransition::new(
            Self::await_success(common.clone(), global_context.clone()),
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
        global_context.await_tx_accepted(common.txid).await
    }

    #[allow(deprecated)]
    async fn transition_success(
        result: Result<(), String>,
        old_state: MintInputStateMachine,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
    ) -> MintInputStateMachine {
        assert!(matches!(old_state.state, MintInputStates::Created(_)));

        match result {
            Ok(()) => {
                // Success case: containing transaction is accepted
                MintInputStateMachine {
                    common: old_state.common,
                    state: MintInputStates::Success(MintInputStateSuccess {}),
                }
            }
            Err(err) => {
                // Transaction rejected: attempting to refund
                debug!(target: LOG_CLIENT_MODULE_MINT, %err, "Refunding mint transaction input due to transaction error");
                Self::refund(dbtx, old_state, global_context).await
            }
        }
    }

    #[allow(deprecated)]
    async fn refund(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: MintInputStateMachine,
        global_context: DynGlobalClientContext,
    ) -> MintInputStateMachine {
        let (amount, spendable_note) = match old_state.state {
            MintInputStates::Created(created) => (created.amount, created.spendable_note),
            _ => panic!("Invalid state transition"),
        };

        let refund_input = ClientInput::<MintInput> {
            input: MintInput::new_v0(amount, spendable_note.note()),
            keys: vec![spendable_note.spend_key],
            amount,
        };

        let (refund_txid, _) = global_context
            .claim_inputs(
                dbtx,
                // The input of the refund tx is managed by this state machine, so no new state
                // machines need to be created
                ClientInputBundle::new_no_sm(vec![refund_input]),
            )
            .await
            .expect("Cannot claim input, additional funding needed");

        MintInputStateMachine {
            common: old_state.common,
            state: MintInputStates::Refund(MintInputStateRefund { refund_txid }),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintInputStateCreatedMulti {
    pub(crate) notes: Vec<(Amount, SpendableNote)>,
}

impl MintInputStateCreatedMulti {
    fn transitions(
        common: &MintInputCommon,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<MintInputStateMachine>> {
        let global_context = global_context.clone();
        vec![StateTransition::new(
            Self::await_success(common.clone(), global_context.clone()),
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
        global_context.await_tx_accepted(common.txid).await
    }

    async fn transition_success(
        result: Result<(), String>,
        old_state: MintInputStateMachine,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
    ) -> MintInputStateMachine {
        assert!(matches!(old_state.state, MintInputStates::CreatedMulti(_)));

        match result {
            Ok(()) => {
                // Success case: containing transaction is accepted
                MintInputStateMachine {
                    common: old_state.common,
                    state: MintInputStates::Success(MintInputStateSuccess {}),
                }
            }
            Err(err) => {
                // Transaction rejected: attempting to refund
                debug!(target: LOG_CLIENT_MODULE_MINT, %err, "Refunding mint transaction input due to transaction error");
                Self::refund(dbtx, old_state, global_context).await
            }
        }
    }

    async fn refund(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: MintInputStateMachine,
        global_context: DynGlobalClientContext,
    ) -> MintInputStateMachine {
        let spendable_notes = match old_state.state {
            MintInputStates::CreatedMulti(created) => created.notes,
            _ => panic!("Invalid state transition"),
        };

        let mut refund_txids = vec![];
        for (amount, spendable_note) in spendable_notes {
            let refund_input = ClientInput::<MintInput> {
                input: MintInput::new_v0(amount, spendable_note.note()),
                keys: vec![spendable_note.spend_key],
                amount,
            };
            let (refund_txid, _) = global_context
                .claim_inputs(
                    dbtx,
                    // The input of the refund tx is managed by this state machine, so no new state
                    // machines need to be created
                    ClientInputBundle::new_no_sm(vec![refund_input]),
                )
                .await
                .expect("Cannot claim input, additional funding needed");

            refund_txids.push(refund_txid);
        }

        assert!(!refund_txids.is_empty());
        MintInputStateMachine {
            common: old_state.common,
            state: MintInputStates::RefundMulti(MintInputStateRefundMulti { refund_txids }),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintInputStateRefund {
    pub refund_txid: TransactionId,
}

impl MintInputStateRefund {
    fn transitions(
        &self,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<MintInputStateMachine>> {
        vec![StateTransition::new(
            Self::await_refund_success(global_context.clone(), self.refund_txid),
            |_dbtx, result, old_state| {
                Box::pin(async { Self::transition_refund_success(result, old_state) })
            },
        )]
    }

    async fn await_refund_success(
        global_context: DynGlobalClientContext,
        refund_txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(refund_txid).await
    }

    fn transition_refund_success(
        result: Result<(), String>,
        old_state: MintInputStateMachine,
    ) -> MintInputStateMachine {
        let refund_txid = match old_state.state {
            MintInputStates::Refund(refund) => refund.refund_txid,
            _ => panic!("Invalid state transition"),
        };

        match result {
            Ok(()) => {
                // Refund successful
                MintInputStateMachine {
                    common: old_state.common,
                    state: MintInputStates::RefundSuccess(MintInputStateRefundSuccess {
                        refund_txid,
                    }),
                }
            }
            Err(err) => {
                // Refund failed
                // TODO: include e-cash notes for recovery? Although, they are in the log …
                warn!(target: LOG_CLIENT_MODULE_MINT, %err, %refund_txid, "Refund transaction rejected. Notes probably lost.");
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintInputStateRefundMulti {
    pub refund_txids: Vec<TransactionId>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintInputStateSuccess {}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintInputStateError {
    error: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintInputStateRefundSuccess {
    refund_txid: TransactionId,
}
