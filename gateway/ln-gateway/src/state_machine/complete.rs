use std::fmt;
use std::time::Duration;

use fedimint_client::sm::{State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_ln_client::incoming::IncomingSmStates;
use fedimint_ln_common::contracts::Preimage;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::{GatewayClientContext, GatewayClientStateMachines};
use crate::lightning::{InterceptPaymentResponse, PaymentAction};

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
enum CompleteHtlcError {
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
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum GatewayCompleteStates {
    WaitForPreimage(WaitForPreimageState),
    CompleteHtlc(CompleteHtlcState),
    HtlcFinished,
    Failure,
}

impl fmt::Display for GatewayCompleteStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayCompleteStates::WaitForPreimage(_) => write!(f, "WaitForPreimage"),
            GatewayCompleteStates::CompleteHtlc(_) => write!(f, "CompleteHtlc"),
            GatewayCompleteStates::HtlcFinished => write!(f, "HtlcFinished"),
            GatewayCompleteStates::Failure => write!(f, "Failure"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct GatewayCompleteCommon {
    pub operation_id: OperationId,
    pub payment_hash: bitcoin::hashes::sha256::Hash,
    pub incoming_chan_id: u64,
    pub htlc_id: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct GatewayCompleteStateMachine {
    pub common: GatewayCompleteCommon,
    pub state: GatewayCompleteStates,
}

impl fmt::Display for GatewayCompleteStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Gateway Complete State Machine Operation ID: {:?} State: {}",
            self.common.operation_id, self.state
        )
    }
}

impl State for GatewayCompleteStateMachine {
    type ModuleContext = GatewayClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        match &self.state {
            GatewayCompleteStates::WaitForPreimage(_state) => {
                WaitForPreimageState::transitions(context.clone(), self.common.clone())
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct WaitForPreimageState;

impl WaitForPreimageState {
    fn transitions(
        context: GatewayClientContext,
        common: GatewayCompleteCommon,
    ) -> Vec<StateTransition<GatewayCompleteStateMachine>> {
        vec![StateTransition::new(
            Self::await_preimage(context, common.clone()),
            move |_dbtx, result, _old_state| {
                let common = common.clone();
                Box::pin(async { Self::transition_complete_htlc(result, common) })
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
            let Some(GatewayClientStateMachines::Receive(state)) = stream.next().await else {
                continue;
            };

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

    fn transition_complete_htlc(
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
enum HtlcOutcome {
    Success(Preimage),
    Failure(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
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
            move |_dbtx, result, _| {
                let common = common.clone();
                Box::pin(async move { Self::transition_success(&result, common) })
            },
        )]
    }

    async fn await_complete_htlc(
        context: GatewayClientContext,
        common: GatewayCompleteCommon,
        htlc_outcome: HtlcOutcome,
    ) -> Result<(), CompleteHtlcError> {
        // Wait until the lightning node is online to complete the HTLC.
        let lightning_context = loop {
            match context.gateway.get_lightning_context().await {
                Ok(lightning_context) => break lightning_context,
                Err(e) => {
                    warn!("Trying to complete HTLC but got {e}, will keep retrying...");
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
            }
        };

        let htlc = InterceptPaymentResponse {
            action: match htlc_outcome {
                HtlcOutcome::Success(preimage) => PaymentAction::Settle(preimage),
                HtlcOutcome::Failure(_) => PaymentAction::Cancel,
            },
            payment_hash: common.payment_hash,
            incoming_chan_id: common.incoming_chan_id,
            htlc_id: common.htlc_id,
        };

        lightning_context
            .lnrpc
            .complete_htlc(htlc)
            .await
            .map_err(|_| CompleteHtlcError::FailedToCompleteHtlc)
    }

    fn transition_success(
        result: &Result<(), CompleteHtlcError>,
        common: GatewayCompleteCommon,
    ) -> GatewayCompleteStateMachine {
        GatewayCompleteStateMachine {
            common,
            state: match result {
                Ok(()) => GatewayCompleteStates::HtlcFinished,
                Err(_) => GatewayCompleteStates::Failure,
            },
        }
    }
}
