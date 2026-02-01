use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::OutPoint;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};

use crate::WalletClientContext;
use crate::api::WalletFederationApi;
use crate::events::{SendPaymentStatus, SendPaymentStatusEvent};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SendStateMachine {
    pub common: SendSMCommon,
    pub state: SendSMState,
}

impl SendStateMachine {
    pub fn update(&self, state: SendSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SendSMCommon {
    pub operation_id: OperationId,
    pub outpoint: OutPoint,
    pub amount: bitcoin::Amount,
    pub fee: bitcoin::Amount,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum SendSMState {
    Funding,
    Success(bitcoin::Txid),
    Aborted(String),
    Failure,
}

impl State for SendStateMachine {
    type ModuleContext = WalletClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let ctx = context.clone();

        match &self.state {
            SendSMState::Funding => {
                vec![StateTransition::new(
                    Self::await_funding(global_context.clone(), self.common.outpoint),
                    move |dbtx, result, old_state| {
                        Box::pin(Self::transition_funding(
                            ctx.clone(),
                            dbtx,
                            result,
                            old_state,
                        ))
                    },
                )]
            }
            SendSMState::Success(_) | SendSMState::Aborted(_) | SendSMState::Failure => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum AwaitFundingResult {
    Success(bitcoin::Txid),
    Aborted(String),
    Failure,
}

impl SendStateMachine {
    async fn await_funding(
        global_context: DynGlobalClientContext,
        outpoint: OutPoint,
    ) -> AwaitFundingResult {
        if let Err(error) = global_context.await_tx_accepted(outpoint.txid).await {
            return AwaitFundingResult::Aborted(error);
        }

        match global_context.module_api().transaction_id(outpoint).await {
            Some(txid) => AwaitFundingResult::Success(txid),
            None => AwaitFundingResult::Failure,
        }
    }

    async fn transition_funding(
        context: WalletClientContext,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        result: AwaitFundingResult,
        old_state: SendStateMachine,
    ) -> SendStateMachine {
        match result {
            AwaitFundingResult::Success(txid) => {
                context
                    .client_ctx
                    .log_event(
                        &mut dbtx.module_tx(),
                        SendPaymentStatusEvent {
                            operation_id: old_state.common.operation_id,
                            status: SendPaymentStatus::Success(txid),
                        },
                    )
                    .await;

                old_state.update(SendSMState::Success(txid))
            }
            AwaitFundingResult::Aborted(error) => {
                context
                    .client_ctx
                    .log_event(
                        &mut dbtx.module_tx(),
                        SendPaymentStatusEvent {
                            operation_id: old_state.common.operation_id,
                            status: SendPaymentStatus::Aborted,
                        },
                    )
                    .await;

                old_state.update(SendSMState::Aborted(error))
            }
            AwaitFundingResult::Failure => old_state.update(SendSMState::Failure),
        }
    }
}
