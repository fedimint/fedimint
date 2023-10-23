use std::time::Duration;

use bitcoin::Txid;
use fedimint_client::sm::{State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::OutPoint;
use fedimint_wallet_common::WalletOutputOutcome;

use crate::WalletClientContext;

// TODO: track tx confirmations
#[aquamarine::aquamarine]
/// graph LR
///     Created --> Success
///     Created --> Aborted
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct WithdrawStateMachine {
    pub(crate) operation_id: OperationId,
    pub(crate) state: WithdrawStates,
}

impl State for WithdrawStateMachine {
    type ModuleContext = WalletClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            WithdrawStates::Created(created) => {
                vec![StateTransition::new(
                    await_withdraw_processed(
                        global_context.clone(),
                        context.clone(),
                        created.clone(),
                    ),
                    |_dbtx, res, old_state| Box::pin(transition_withdraw_processed(res, old_state)),
                )]
            }
            WithdrawStates::Success(_) => {
                vec![]
            }
            WithdrawStates::Aborted(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

async fn await_withdraw_processed(
    global_context: DynGlobalClientContext,
    context: WalletClientContext,
    created: CreatedWithdrawState,
) -> Result<Txid, String> {
    global_context
        .api()
        .await_output_outcome::<WalletOutputOutcome>(
            created.fm_outpoint,
            Duration::MAX,
            &context.wallet_decoder,
        )
        .await
        .map(|outcome| outcome.0)
        .map_err(|e| e.to_string())
}

async fn transition_withdraw_processed(
    res: Result<Txid, String>,
    old_state: WithdrawStateMachine,
) -> WithdrawStateMachine {
    assert!(
        matches!(old_state.state, WithdrawStates::Created(_)),
        "Unexpected old state: got {:?}, expected Created",
        old_state.state
    );

    let new_state = match res {
        Ok(txid) => WithdrawStates::Success(SuccessWithdrawState { txid }),
        Err(error) => WithdrawStates::Aborted(AbortedWithdrawState { error }),
    };

    WithdrawStateMachine {
        operation_id: old_state.operation_id,
        state: new_state,
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum WithdrawStates {
    Created(CreatedWithdrawState),
    Success(SuccessWithdrawState),
    Aborted(AbortedWithdrawState),
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct CreatedWithdrawState {
    pub(crate) fm_outpoint: OutPoint,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct SuccessWithdrawState {
    pub(crate) txid: Txid,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct AbortedWithdrawState {
    pub(crate) error: String,
}
