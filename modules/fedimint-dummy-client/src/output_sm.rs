use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::AmountUnit;
use fedimint_core::{Amount, OutPoint};

use crate::DummyClientContext;
use crate::db::DummyClientFundsKey;

/// State machine tracking receiving (outputs).
///
/// Balance is NOT added immediately. On acceptance, balance is added.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct DummyOutputStateMachine {
    pub common: DummyOutputSMCommon,
    pub state: DummyOutputSMState,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct DummyOutputSMCommon {
    pub operation_id: OperationId,
    pub out_point: OutPoint,
    pub amount: Amount,
    pub unit: AmountUnit,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum DummyOutputSMState {
    Created,
    Accepted,
    Rejected,
}

impl DummyOutputStateMachine {
    fn update(&self, state: DummyOutputSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

impl State for DummyOutputStateMachine {
    type ModuleContext = DummyClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self.state {
            DummyOutputSMState::Created => {
                let global = global_context.clone();
                let txid = self.common.out_point.txid;
                let balance_update_sender = context.balance_update_sender.clone();

                vec![StateTransition::new(
                    async move { global.await_tx_accepted(txid).await },
                    move |dbtx, result, old_state| {
                        Box::pin(Self::transition_created(
                            dbtx,
                            result,
                            old_state,
                            balance_update_sender.clone(),
                        ))
                    },
                )]
            }
            DummyOutputSMState::Accepted | DummyOutputSMState::Rejected => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl DummyOutputStateMachine {
    async fn transition_created(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        result: Result<(), String>,
        old_state: Self,
        balance_update_sender: tokio::sync::watch::Sender<()>,
    ) -> Self {
        if result.is_ok() {
            let current = dbtx
                .module_tx()
                .get_value(&DummyClientFundsKey(old_state.common.unit))
                .await
                .unwrap_or(Amount::ZERO);

            dbtx.module_tx()
                .insert_entry(
                    &DummyClientFundsKey(old_state.common.unit),
                    &(current + old_state.common.amount),
                )
                .await;

            dbtx.module_tx().on_commit(move || {
                balance_update_sender.send_replace(());
            });

            old_state.update(DummyOutputSMState::Accepted)
        } else {
            old_state.update(DummyOutputSMState::Rejected)
        }
    }
}
