use std::fmt;

use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_lightning::common::Preimage;
use fedimint_lightning::{InterceptPaymentResponse, PaymentAction};
use fedimint_lnv2_common::contracts::PaymentImage;

use super::events::CompleteLightningPaymentSucceeded;
use super::FinalReceiveState;
use crate::GatewayClientContextV2;

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

impl fmt::Display for CompleteStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Complete State Machine Operation ID: {:?} State: {}",
            self.common.operation_id, self.state
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct CompleteSMCommon {
    pub operation_id: OperationId,
    pub payment_hash: bitcoin::hashes::sha256::Hash,
    pub incoming_chan_id: u64,
    pub htlc_id: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum CompleteSMState {
    Pending,
    Completing(FinalReceiveState),
    Completed,
}

impl fmt::Display for CompleteSMState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompleteSMState::Pending => write!(f, "Pending"),
            CompleteSMState::Completing(_) => write!(f, "Completing"),
            CompleteSMState::Completed => write!(f, "Completed"),
        }
    }
}

impl State for CompleteStateMachine {
    type ModuleContext = GatewayClientContextV2;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gateway_context = context.clone();
        match &self.state {
            CompleteSMState::Pending => vec![StateTransition::new(
                Self::await_receive(context.clone(), self.common.operation_id),
                |_, result, old_state| {
                    Box::pin(async move { Self::transition_receive(result, &old_state) })
                },
            )],
            CompleteSMState::Completing(finale_receive_state) => vec![StateTransition::new(
                Self::await_completion(
                    gateway_context.clone(),
                    self.common.payment_hash,
                    finale_receive_state.clone(),
                    self.common.incoming_chan_id,
                    self.common.htlc_id,
                ),
                move |dbtx, (), old_state| {
                    Box::pin(Self::transition_completion(
                        old_state,
                        dbtx,
                        gateway_context.clone(),
                    ))
                },
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
    ) -> FinalReceiveState {
        context.module.await_receive(operation_id).await
    }

    fn transition_receive(
        final_receive_state: FinalReceiveState,
        old_state: &CompleteStateMachine,
    ) -> CompleteStateMachine {
        old_state.update(CompleteSMState::Completing(final_receive_state))
    }

    async fn await_completion(
        context: GatewayClientContextV2,
        payment_hash: bitcoin::hashes::sha256::Hash,
        final_receive_state: FinalReceiveState,
        incoming_chan_id: u64,
        htlc_id: u64,
    ) {
        let action = if let FinalReceiveState::Success(preimage) = final_receive_state {
            PaymentAction::Settle(Preimage(preimage))
        } else {
            PaymentAction::Cancel
        };

        let intercept_htlc_response = InterceptPaymentResponse {
            incoming_chan_id,
            htlc_id,
            payment_hash,
            action,
        };

        context.gateway.complete_htlc(intercept_htlc_response).await;
    }

    async fn transition_completion(
        old_state: CompleteStateMachine,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        client_ctx: GatewayClientContextV2,
    ) -> CompleteStateMachine {
        client_ctx
            .module
            .client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                CompleteLightningPaymentSucceeded {
                    payment_image: PaymentImage::Hash(old_state.common.payment_hash),
                },
            )
            .await;
        old_state.update(CompleteSMState::Completed)
    }
}
