use fedimint_client::sm::{State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_ln_client::incoming::IncomingSmStates;
use fedimint_ln_common::contracts::Preimage;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::{GatewayClientContext, GatewayClientStateMachines};
use crate::gateway_lnrpc::intercept_htlc_response::{Action, Cancel, Settle};
use crate::gateway_lnrpc::InterceptHtlcResponse;

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum CompleteHtlcError {
    #[error("Incoming contract was not funded")]
    IncomingContractNotFunded,
    #[error("Failed to complete HTLC")]
    FailedToCompleteHtlc,
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that completes the incoming payment by contacting the
/// lightning node when the incoming contract has been funded and the preimage
/// is available.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    WaitForPreimage -- incoming contract not funded --> Failure
///    WaitForPreimage -- successfully retrieved preimage --> CompleteHtlc
///    CompleteHtlc -- successfully completed or canceled htlc --> HtlcFinished
///    CompleteHtlc -- failed to finish htlc --> Failure
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GatewayCompleteStates {
    WaitForPreimage(WaitForPreimageState),
    CompleteHtlc(CompleteHtlcState),
    HtlcFinished,
    Failure,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayCompleteCommon {
    pub operation_id: OperationId,
    pub incoming_chan_id: u64,
    pub htlc_id: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayCompleteStateMachine {
    pub common: GatewayCompleteCommon,
    pub state: GatewayCompleteStates,
}

impl State for GatewayCompleteStateMachine {
    type ModuleContext = GatewayClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        _global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        match &self.state {
            GatewayCompleteStates::WaitForPreimage(state) => {
                state.transitions(context.clone(), self.common.clone())
            }
            GatewayCompleteStates::CompleteHtlc(state) => {
                state.transitions(context.clone(), self.common.clone())
            }
            _ => vec![],
        }
    }

    fn operation_id(&self) -> fedimint_core::core::OperationId {
        self.common.operation_id
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct WaitForPreimageState;

impl WaitForPreimageState {
    fn transitions(
        &self,
        context: GatewayClientContext,
        common: GatewayCompleteCommon,
    ) -> Vec<StateTransition<GatewayCompleteStateMachine>> {
        vec![StateTransition::new(
            Self::await_preimage(context, common.clone()),
            move |_dbtx, result, _old_state| {
                Box::pin(Self::transition_complete_htlc(result, common.clone()))
            },
        )]
    }

    async fn await_preimage(
        context: GatewayClientContext,
        common: GatewayCompleteCommon,
    ) -> Result<Preimage, CompleteHtlcError> {
        let mut stream = context.notifier.subscribe(common.operation_id).await;
        loop {
            debug!("Waiting for preimage for {common:?}");
            if let Some(GatewayClientStateMachines::Receive(state)) = stream.next().await {
                match state.state {
                    IncomingSmStates::Preimage(preimage) => {
                        debug!("Received preimage for {common:?}");
                        return Ok(preimage);
                    }
                    IncomingSmStates::RefundSubmitted { out_points, error } => {
                        info!("Refund submitted for {common:?}: {out_points:?} {error}");
                        return Err(CompleteHtlcError::IncomingContractNotFunded);
                    }
                    IncomingSmStates::FundingFailed { error } => {
                        warn!("Funding failed for {common:?}: {error}");
                        return Err(CompleteHtlcError::IncomingContractNotFunded);
                    }
                    _ => {}
                }
            }
        }
    }

    async fn transition_complete_htlc(
        result: Result<Preimage, CompleteHtlcError>,
        common: GatewayCompleteCommon,
    ) -> GatewayCompleteStateMachine {
        match result {
            Ok(preimage) => GatewayCompleteStateMachine {
                common,
                state: GatewayCompleteStates::CompleteHtlc(CompleteHtlcState {
                    outcome: HtlcOutcome::Success(preimage),
                }),
            },
            Err(e) => GatewayCompleteStateMachine {
                common,
                state: GatewayCompleteStates::CompleteHtlc(CompleteHtlcState {
                    outcome: HtlcOutcome::Failure(e.to_string()),
                }),
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum HtlcOutcome {
    Success(Preimage),
    Failure(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct CompleteHtlcState {
    outcome: HtlcOutcome,
}

impl CompleteHtlcState {
    fn transitions(
        &self,
        context: GatewayClientContext,
        common: GatewayCompleteCommon,
    ) -> Vec<StateTransition<GatewayCompleteStateMachine>> {
        vec![StateTransition::new(
            Self::await_complete_htlc(context, common.clone(), self.outcome.clone()),
            move |_dbtx, result, _| Box::pin(Self::transition_success(result, common.clone())),
        )]
    }

    async fn await_complete_htlc(
        context: GatewayClientContext,
        common: GatewayCompleteCommon,
        outcome: HtlcOutcome,
    ) -> Result<(), CompleteHtlcError> {
        let htlc = match outcome {
            HtlcOutcome::Success(preimage) => InterceptHtlcResponse {
                action: Some(Action::Settle(Settle {
                    preimage: preimage.0.to_vec(),
                })),
                incoming_chan_id: common.incoming_chan_id,
                htlc_id: common.htlc_id,
            },
            HtlcOutcome::Failure(reason) => InterceptHtlcResponse {
                action: Some(Action::Cancel(Cancel { reason })),
                incoming_chan_id: common.incoming_chan_id,
                htlc_id: common.htlc_id,
            },
        };

        // TODO: Can we retry this instead of failing?
        context
            .lnrpc
            .complete_htlc(htlc)
            .await
            .map_err(|_| CompleteHtlcError::FailedToCompleteHtlc)?;
        Ok(())
    }

    async fn transition_success(
        result: Result<(), CompleteHtlcError>,
        common: GatewayCompleteCommon,
    ) -> GatewayCompleteStateMachine {
        match result {
            Ok(_) => GatewayCompleteStateMachine {
                common,
                state: GatewayCompleteStates::HtlcFinished,
            },
            Err(_) => GatewayCompleteStateMachine {
                common,
                state: GatewayCompleteStates::Failure,
            },
        }
    }
}
