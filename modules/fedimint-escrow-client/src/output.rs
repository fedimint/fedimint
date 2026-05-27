use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{State, StateTransition};
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint};
use fedimint_escrow_common::EscrowId;
use serde::{Deserialize, Serialize};
use crate::EscrowClientContext;
use crate::client_db::{ClientEscrowKey, EscrowClientRecord, EscrowClientStatus};

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
                        |dbtx, result, old_state:EscrowOutputStateMachine| Box::pin(async move{
                            EscrowOutputStateMachine {
                                common: old_state.common.clone(),
                                state: match result {
                                    Ok(_)  => {
                                        let _= dbtx.module_tx().insert_entry(
                                            &ClientEscrowKey(old_state.common.escrow_id), 
                                            &EscrowClientRecord {
                                                escrow_id: old_state.common.escrow_id,
                                                operation_id: old_state.common.operation_id,
                                                amount: old_state.common.amount,
                                                status: EscrowClientStatus::Active,
                                            }
                                        ).await;
                                        EscrowOutputSMState::Active
                                    }
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
