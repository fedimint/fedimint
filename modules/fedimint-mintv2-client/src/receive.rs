use fedimint_client::DynGlobalClientContext;
use fedimint_client_module::module::ClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::TransactionId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};

use crate::event::{ReceivePaymentStatus, ReceivePaymentUpdateEvent};
use crate::{MintClientContext, MintClientModule};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct ReceiveStateMachine {
    pub operation_id: OperationId,
    pub txid: TransactionId,
    pub state: ReceiveSMState,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum ReceiveSMState {
    Pending,
    Success,
    Rejected,
}

impl State for ReceiveStateMachine {
    type ModuleContext = MintClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let client_ctx = context.client_ctx.clone();

        match &self.state {
            ReceiveSMState::Pending => vec![StateTransition::new(
                Self::await_tx_outcome(global_context.clone(), self.txid),
                move |dbtx, accepted, old_state| {
                    Box::pin(Self::transition_tx_outcome(
                        client_ctx.clone(),
                        dbtx,
                        accepted,
                        old_state,
                    ))
                },
            )],
            ReceiveSMState::Success | ReceiveSMState::Rejected => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

impl ReceiveStateMachine {
    async fn await_tx_outcome(global_context: DynGlobalClientContext, txid: TransactionId) -> bool {
        global_context.await_tx_accepted(txid).await.is_ok()
    }

    async fn transition_tx_outcome(
        client_ctx: ClientContext<MintClientModule>,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        accepted: bool,
        old_state: ReceiveStateMachine,
    ) -> ReceiveStateMachine {
        let (status, new_state) = if accepted {
            (ReceivePaymentStatus::Success, ReceiveSMState::Success)
        } else {
            (ReceivePaymentStatus::Rejected, ReceiveSMState::Rejected)
        };

        client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                ReceivePaymentUpdateEvent {
                    operation_id: old_state.operation_id,
                    status,
                },
            )
            .await;

        ReceiveStateMachine {
            operation_id: old_state.operation_id,
            txid: old_state.txid,
            state: new_state,
        }
    }
}
