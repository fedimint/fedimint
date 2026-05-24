use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{State, StateTransition};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint};
use fedimint_escrow_common::EscrowId;
use serde::{Deserialize, Serialize};
use crate::EscrowClientContext;

// state machines for contract creation (output)
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct EscrowOutputStateMachine{
    pub common:EscrowOutputSMCommon,
    pub state:EscrowOutputSMState
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct EscrowOutputSMCommon{
    pub operation_id: OperationId,
    pub out_point: OutPoint,
    pub amount: Amount,
    pub escrow_id:EscrowId,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub enum EscrowOutputSMState{
    Creating,
    Active,
    Failed {reason: String},
}

impl EscrowOutputStateMachine{
    #[allow(dead_code)]
    fn update(&self,state:EscrowOutputSMState)->Self{
        Self { common: self.common.clone(), state }
    }
    #[allow(dead_code)]
    fn escrow_id(&self)->EscrowId{
        self.common.escrow_id
    }
}

impl State for EscrowOutputStateMachine {
    type ModuleContext = EscrowClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>>
    {
        match self.state {
            EscrowOutputSMState::Creating=>{
                let txid=self.common.out_point.txid;
                let global_context=global_context.clone();

                vec![
                    StateTransition::new(
                        async move { global_context.await_tx_accepted(txid).await },
                        |_dbtx, result, old_state:EscrowOutputStateMachine| Box::pin(async move{
                            EscrowOutputStateMachine {
                                common: old_state.common,
                                state: match result {
                                    Ok(_)  => EscrowOutputSMState::Active,
                                    Err(e) => EscrowOutputSMState::Failed { reason: e },
                                },
                            }
                        }),
                    )
                ]
            }
            EscrowOutputSMState::Active | EscrowOutputSMState::Failed { .. } => vec![]
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}
