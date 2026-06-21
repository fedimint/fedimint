use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{State, StateTransition};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint};
use fedimint_escrow_common::{EscrowId, Outcome, Resolution};
use serde::{Deserialize, Serialize};

use crate::EscrowClientContext;

// state machines for contract resolution (input)
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct EscrowInputStateMachine {
    pub common: EscrowInputSMCommon,
    pub state: EscrowInputSMState,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct EscrowInputSMCommon {
    pub operation_id: OperationId,
    pub out_point: OutPoint,
    pub amount: Amount,
    pub escrow_id: EscrowId,
    pub resolution: Resolution,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub enum EscrowInputSMState {
    Refunded,
    Released,
    Pending,
    FeeClaimed,
    FeeClaiming,
    Failed { reason: String },
}

impl EscrowInputStateMachine {
    #[allow(dead_code)]
    fn update(&self, state: EscrowInputSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

impl State for EscrowInputStateMachine {
    type ModuleContext = EscrowClientContext;

    fn transitions(
        &self,
        _ctx: &EscrowClientContext,
        global: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self.state {
            EscrowInputSMState::Pending => {
                let global = global.clone();
                let txid = self.common.out_point.txid;

                vec![StateTransition::new(
                    async move { global.await_tx_accepted(txid).await },
                    |_dbtx, result, old_state: EscrowInputStateMachine| {
                        Box::pin(async move {
                            let new_state = match result {
                                Ok(()) => match &old_state.common.resolution {
                                    Resolution::BuyerRelease { .. } => EscrowInputSMState::Released,
                                    Resolution::ArbiterOutcome { outcome, .. } => match outcome {
                                        Outcome::Release => EscrowInputSMState::Released,
                                        Outcome::Refund => EscrowInputSMState::Refunded,
                                    },
                                    Resolution::ArbiterFeeClaim { .. } => {
                                        EscrowInputSMState::Failed {
                                            reason: "unexpected: fee claim in resolution state"
                                                .into(),
                                        }
                                    }
                                },
                                Err(e) => EscrowInputSMState::Failed { reason: e },
                            };

                            EscrowInputStateMachine {
                                common: old_state.common.clone(),
                                state: new_state,
                            }
                        })
                    },
                )]
            }
            EscrowInputSMState::FeeClaiming => {
                let txid = self.common.out_point.txid;
                let global_context = global.clone();

                vec![StateTransition::new(
                    async move { global_context.await_tx_accepted(txid).await },
                    |_dbtx, result, old_state: EscrowInputStateMachine| {
                        Box::pin(async move {
                            EscrowInputStateMachine {
                                common: old_state.common.clone(),
                                state: match result {
                                    Ok(_) => EscrowInputSMState::FeeClaimed,
                                    Err(e) => EscrowInputSMState::Failed { reason: e },
                                },
                            }
                        })
                    },
                )]
            }
            _ => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}
