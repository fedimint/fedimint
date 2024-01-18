use std::time::Duration;

use bitcoin::Txid;
use fedimint_client::sm::{State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::{GlobalFederationApi, OutputOutcomeError};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::OutPoint;
use fedimint_wallet_common::WalletOutputOutcome;
use tracing::debug;

use crate::WalletClientContext;

const RETRY_DELAY: Duration = Duration::from_secs(1);

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
                        self.operation_id,
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
    operation_id: OperationId,
    created: CreatedWithdrawState,
) -> Result<Txid, String> {
    global_context
        .await_tx_accepted(operation_id, created.fm_outpoint.txid)
        .await?;

    loop {
        match global_context
            .api()
            .await_output_outcome::<WalletOutputOutcome>(
                created.fm_outpoint,
                Duration::MAX,
                &context.wallet_decoder,
            )
            .await
        {
            Ok(outcome) => {
                return outcome
                    .ensure_v0_ref()
                    .map(|outcome| outcome.0)
                    .map_err(|e| e.to_string())
            }
            Err(OutputOutcomeError::Federation(e)) => {
                e.report_if_important();
                debug!(
                    "Awaiting output outcome failed, retrying in {}s",
                    RETRY_DELAY.as_secs_f64()
                );
                sleep(RETRY_DELAY).await;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
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
