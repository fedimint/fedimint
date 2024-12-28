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
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum InputSMState {
    Pending,
    Success,
    Refunding(OutPointRange),
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
            InputSMState::Success | InputSMState::Refunding(..) => {
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

        InputStateMachine {
            common: old_state.common,
            state: InputSMState::Refunding(change_range),
        }
    }
}
