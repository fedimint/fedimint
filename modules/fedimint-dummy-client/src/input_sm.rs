use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::AmountUnit;
use fedimint_core::{Amount, OutPoint};

use crate::DummyClientContext;
use crate::db::DummyClientFundsKey;

/// State machine tracking spending (inputs).
///
/// Balance is subtracted immediately when created. On rejection, balance is
/// refunded.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct DummyInputStateMachine {
    pub common: DummyInputSMCommon,
    pub state: DummyInputSMState,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct DummyInputSMCommon {
    pub operation_id: OperationId,
    pub out_point: OutPoint,
    pub amount: Amount,
    pub unit: AmountUnit,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum DummyInputSMState {
    Created,
    Accepted,
    Refunded,
}

impl DummyInputStateMachine {
    fn update(&self, state: DummyInputSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

impl State for DummyInputStateMachine {
    type ModuleContext = DummyClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self.state {
            DummyInputSMState::Created => {
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
            DummyInputSMState::Accepted | DummyInputSMState::Refunded => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl DummyInputStateMachine {
    async fn transition_created(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        result: Result<(), String>,
        old_state: Self,
        balance_update_sender: tokio::sync::watch::Sender<()>,
    ) -> Self {
        if result.is_ok() {
            old_state.update(DummyInputSMState::Accepted)
        } else {
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

            old_state.update(DummyInputSMState::Refunded)
        }
    }
}
