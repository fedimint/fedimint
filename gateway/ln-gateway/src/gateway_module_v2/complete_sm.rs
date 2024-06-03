use std::time::Duration;

use fedimint_client::sm::{State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use futures::StreamExt;
use tracing::warn;

use crate::gateway_lnrpc::intercept_htlc_response::{Action, Cancel, Settle};
use crate::gateway_lnrpc::InterceptHtlcResponse;
use crate::gateway_module_v2::receive_sm::ReceiveSMState;
use crate::gateway_module_v2::{GatewayClientContextV2, GatewayClientStateMachinesV2};

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that completes the incoming payment by contacting the
/// lightning node when the incoming contract has been funded and the preimage
/// is available.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    Pending -- receive preimage or fail --> Completing
///    Completing -- htlc is completed  --> Completed
/// ```

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct CompleteStateMachine {
    pub common: CompleteSMCommon,
    pub state: CompleteSMState,
}

impl CompleteStateMachine {
    pub fn update(&self, state: CompleteSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct CompleteSMCommon {
    pub operation_id: OperationId,
    pub incoming_chan_id: u64,
    pub htlc_id: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum CompleteSMState {
    Pending,
    Completing(Result<[u8; 32], String>),
    Completed,
}

impl State for CompleteStateMachine {
    type ModuleContext = GatewayClientContextV2;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            CompleteSMState::Pending => vec![StateTransition::new(
                Self::await_receive(context.clone(), self.common.operation_id),
                |_, result, old_state| {
                    Box::pin(async move { Self::transition_receive(result, &old_state) })
                },
            )],
            CompleteSMState::Completing(result) => vec![StateTransition::new(
                Self::await_completion(
                    context.clone(),
                    self.common.incoming_chan_id,
                    self.common.htlc_id,
                    result.clone(),
                ),
                |_, (), old_state| Box::pin(async move { Self::transition_completion(&old_state) }),
            )],
            CompleteSMState::Completed => Vec::new(),
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl CompleteStateMachine {
    async fn await_receive(
        context: GatewayClientContextV2,
        operation_id: OperationId,
    ) -> Result<[u8; 32], String> {
        let mut stream = context.notifier.subscribe(operation_id).await;

        loop {
            if let Some(GatewayClientStateMachinesV2::Receive(state)) = stream.next().await {
                match state.state {
                    ReceiveSMState::Funding => {}
                    ReceiveSMState::Rejected(error) => {
                        return Err(error);
                    }
                    ReceiveSMState::Success(preimage) => {
                        return Ok(preimage);
                    }
                    ReceiveSMState::Failure => {
                        return Err("Failure".to_string());
                    }
                    ReceiveSMState::Refunding(..) => {
                        return Err("Refunding".to_string());
                    }
                }
            }
        }
    }

    fn transition_receive(
        result: Result<[u8; 32], String>,
        old_state: &CompleteStateMachine,
    ) -> CompleteStateMachine {
        old_state.update(CompleteSMState::Completing(result))
    }

    async fn await_completion(
        context: GatewayClientContextV2,
        incoming_chan_id: u64,
        htlc_id: u64,
        result: Result<[u8; 32], String>,
    ) {
        let action = match result {
            Ok(preimage) => Action::Settle(Settle {
                preimage: preimage.to_vec(),
            }),
            Err(reason) => Action::Cancel(Cancel { reason }),
        };

        let intercept_htlc_response = InterceptHtlcResponse {
            action: Some(action),
            incoming_chan_id,
            htlc_id,
        };

        loop {
            match context.gateway.get_lightning_context().await {
                Ok(lightning_context) => {
                    match lightning_context
                        .lnrpc
                        .complete_htlc(intercept_htlc_response.clone())
                        .await
                    {
                        Ok(..) => return,
                        Err(error) => {
                            warn!("Trying to complete HTLC but got {error}, will keep retrying...");
                        }
                    }
                }
                Err(error) => {
                    warn!("Trying to complete HTLC but got {error}, will keep retrying...");
                }
            }

            sleep(Duration::from_secs(5)).await;
        }
    }

    fn transition_completion(old_state: &CompleteStateMachine) -> CompleteStateMachine {
        old_state.update(CompleteSMState::Completed)
    }
}
