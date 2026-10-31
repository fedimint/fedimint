use fedimint_client::DynGlobalClientContext;
use fedimint_client::transaction::{ClientInput, ClientInputBundle};
use fedimint_client_module::module::OutPointRange;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::TransactionId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_mintv2_common::MintInput;

use crate::{MintClientContext, SpendableNote};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct InputStateMachine {
    pub common: InputSMCommon,
    pub state: InputSMState,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Decodable, Encodable)]
pub struct InputSMCommon {
    pub operation_id: OperationId,
    pub txid: TransactionId,
    pub spendable_notes: Vec<SpendableNote>,
    pub refund_txid: Option<TransactionId>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum InputSMState {
    Pending,
    Success,
    Refunding(OutPointRange),
    RefundSettled,
    RefundFailed { refund_txid: TransactionId },
}

impl State for InputStateMachine {
    type ModuleContext = MintClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();

        match &self.state {
            InputSMState::Pending => {
                vec![StateTransition::new(
                    Self::await_pending_transaction(gc.clone(), self.common.txid),
                    move |dbtx, result, old_state| {
                        Box::pin(Self::transition_pending_transaction(
                            gc.clone(),
                            dbtx,
                            result,
                            old_state,
                        ))
                    },
                )]
            }
            InputSMState::Refunding(_) => {
                let refund_txid = self.common.refund_txid.expect("refund_txid must be set");
                vec![StateTransition::new(
                    Self::await_refund_settlement(gc.clone(), refund_txid),
                    move |_dbtx, result, old_state| {
                        let result_ref = result.clone();
                        Box::pin(async move {
                            Self::transition_refund_settlement(&result_ref, old_state)
                        })
                    },
                )]
            }
            InputSMState::RefundFailed { .. } => {
                vec![StateTransition::new(
                    async { Ok::<(), String>(()) },
                    move |dbtx, _result, old_state| {
                        Box::pin(Self::retry_refund(gc.clone(), dbtx, old_state))
                    },
                )]
            }
            InputSMState::Success | InputSMState::RefundSettled => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl InputStateMachine {
    async fn await_pending_transaction(
        global_context: DynGlobalClientContext,
        txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(txid).await
    }

    async fn transition_pending_transaction(
        global_context: DynGlobalClientContext,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        result: Result<(), String>,
        old_state: InputStateMachine,
    ) -> InputStateMachine {
        if result.is_ok() {
            return InputStateMachine {
                common: old_state.common,
                state: InputSMState::Success,
            };
        }

        let inputs = old_state
            .common
            .spendable_notes
            .iter()
            .map(|spendable_note| ClientInput::<MintInput> {
                input: MintInput::new_v0(spendable_note.note()),
                keys: vec![spendable_note.keypair],
                amounts: Amounts::new_bitcoin(spendable_note.amount()),
            })
            .collect();

        let change_range = global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(inputs))
            .await
            .expect("Cannot claim input, additional funding needed");

        let refund_txid = change_range.txid();
        InputStateMachine {
            common: InputSMCommon {
                operation_id: old_state.common.operation_id,
                txid: old_state.common.txid,
                spendable_notes: old_state.common.spendable_notes,
                refund_txid: Some(refund_txid),
            },
            state: InputSMState::Refunding(change_range),
        }
    }

    async fn await_refund_settlement(
        global_context: DynGlobalClientContext,
        refund_txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(refund_txid).await
    }

    fn transition_refund_settlement(
        result: &Result<(), String>,
        old_state: InputStateMachine,
    ) -> InputStateMachine {
        if let Ok(()) = result {
            InputStateMachine {
                common: old_state.common.clone(),
                state: InputSMState::RefundSettled,
            }
        } else {
            let refund_txid = old_state
                .common
                .refund_txid
                .expect("refund_txid must be set");
            InputStateMachine {
                common: old_state.common,
                state: InputSMState::RefundFailed { refund_txid },
            }
        }
    }

    async fn retry_refund(
        global_context: DynGlobalClientContext,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: InputStateMachine,
    ) -> InputStateMachine {
        let inputs = old_state
            .common
            .spendable_notes
            .iter()
            .map(|spendable_note| ClientInput::<MintInput> {
                input: MintInput::new_v0(spendable_note.note()),
                keys: vec![spendable_note.keypair],
                amounts: Amounts::new_bitcoin(spendable_note.amount()),
            })
            .collect();

        match global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(inputs))
            .await
        {
            Ok(change_range) => {
                let refund_txid = change_range.txid();
                InputStateMachine {
                    common: InputSMCommon {
                        operation_id: old_state.common.operation_id,
                        txid: old_state.common.txid,
                        spendable_notes: old_state.common.spendable_notes,
                        refund_txid: Some(refund_txid),
                    },
                    state: InputSMState::Refunding(change_range),
                }
            }
            Err(_) => old_state,
        }
    }
}
