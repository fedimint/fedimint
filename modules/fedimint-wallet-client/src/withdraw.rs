use bitcoin::Txid;
use fedimint_api_client::api::{deserialize_outcome, FederationApiExt};
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client_module::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
#[allow(deprecated)]
use fedimint_core::endpoint_constants::AWAIT_OUTPUT_OUTCOME_ENDPOINT;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::OutPoint;
use fedimint_wallet_common::WalletOutputOutcome;
use futures::future::pending;
use tracing::warn;

use crate::events::WithdrawRequest;
use crate::WalletClientContext;

// TODO: track tx confirmations
#[aquamarine::aquamarine]
/// graph LR
///     Created --> Success
///     Created --> Aborted
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct WithdrawStateMachine {
    pub(crate) operation_id: OperationId,
    pub(crate) state: WithdrawStates,
}

impl State for WithdrawStateMachine {
    type ModuleContext = WalletClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let wallet_context = context.clone();
        match &self.state {
            WithdrawStates::Created(created) => {
                vec![StateTransition::new(
                    await_withdraw_processed(
                        global_context.clone(),
                        context.clone(),
                        created.clone(),
                    ),
                    move |dbtx, res, old_state| {
                        Box::pin(transition_withdraw_processed(
                            res,
                            old_state,
                            wallet_context.clone(),
                            dbtx,
                        ))
                    },
                )]
            }
            WithdrawStates::Success(_) | WithdrawStates::Aborted(_) => {
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
        .await_tx_accepted(created.fm_outpoint.txid)
        .await?;

    #[allow(deprecated)]
    let outcome = global_context
        .api()
        .request_current_consensus_retry(
            AWAIT_OUTPUT_OUTCOME_ENDPOINT.to_owned(),
            ApiRequestErased::new(created.fm_outpoint),
        )
        .await;

    match deserialize_outcome::<WalletOutputOutcome>(&outcome, &context.wallet_decoder)
        .map_err(|e| e.to_string())
        .and_then(|outcome| {
            outcome
                .ensure_v0_ref()
                .map(|outcome| outcome.0)
                .map_err(|e| e.to_string())
        }) {
        Ok(txid) => Ok(txid),
        Err(e) => {
            warn!("Failed to process wallet output outcome: {e}");

            pending().await
        }
    }
}

async fn transition_withdraw_processed(
    res: Result<Txid, String>,
    old_state: WithdrawStateMachine,
    client_ctx: WalletClientContext,
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
) -> WithdrawStateMachine {
    assert!(
        matches!(old_state.state, WithdrawStates::Created(_)),
        "Unexpected old state: got {:?}, expected Created",
        old_state.state
    );

    let new_state = match res {
        Ok(txid) => {
            client_ctx
                .client_ctx
                .log_event(&mut dbtx.module_tx(), WithdrawRequest { txid })
                .await;
            WithdrawStates::Success(SuccessWithdrawState { txid })
        }
        Err(error) => WithdrawStates::Aborted(AbortedWithdrawState { error }),
    };

    WithdrawStateMachine {
        operation_id: old_state.operation_id,
        state: new_state,
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum WithdrawStates {
    Created(CreatedWithdrawState),
    Success(SuccessWithdrawState),
    Aborted(AbortedWithdrawState),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct CreatedWithdrawState {
    pub(crate) fm_outpoint: OutPoint,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SuccessWithdrawState {
    pub(crate) txid: Txid,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct AbortedWithdrawState {
    pub(crate) error: String,
}
