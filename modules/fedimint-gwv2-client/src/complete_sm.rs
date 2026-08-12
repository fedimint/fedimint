use std::fmt;

use fedimint_client::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_lightning::{InterceptPaymentResponse, LightningRpcError, PaymentAction, Preimage};
use fedimint_lnv2_common::contracts::PaymentImage;

use super::FinalReceiveState;
use super::events::CompleteLightningPaymentSucceeded;
use crate::GatewayClientContextV2;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that completes the incoming payment by contacting the
/// lightning node when the incoming contract has been funded and the preimage
/// is available.
///
/// This is the legacy combined-operation representation. It remains decodable
/// so upgrades can resume existing operations; new incoming circuits use
/// [`CircuitCompleteStateMachine`].
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    Pending -- receive preimage or fail --> Completing
///    Completing -- htlc is completed  --> Completed
///    Completing -- permanent outcome conflict --> CompletionFailed
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

/// State machine that completes one distinct incoming Lightning circuit.
///
/// New incoming payments use this state machine. [`CompleteStateMachine`]
/// remains in the state enum so clients can decode and resume operations
/// created before circuit-specific completion operations were introduced.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct CircuitCompleteStateMachine {
    /// Data shared by every state of this circuit completion.
    pub common: CircuitCompleteSMCommon,
    /// Current completion state.
    pub state: CompleteSMState,
}

/// Data needed to complete a distinct incoming Lightning circuit.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct CircuitCompleteSMCommon {
    /// Circuit-specific operation identifier.
    pub operation_id: OperationId,
    /// Original receive operation whose result determines the outcome.
    pub receive_operation_id: OperationId,
    /// Payment hash carried by the incoming HTLC.
    pub payment_hash: bitcoin::hashes::sha256::Hash,
    /// Incoming circuit to resolve.
    pub circuit: IncomingCircuitKey,
}

/// Stable identity of an incoming Lightning circuit.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct IncomingCircuitKey {
    /// Incoming channel identifier, or the no-circuit marker.
    pub incoming_chan_id: u64,
    /// Incoming HTLC identifier, or the no-circuit marker.
    pub htlc_id: u64,
}

async fn await_receive(
    context: GatewayClientContextV2,
    operation_id: OperationId,
) -> FinalReceiveState {
    context.module.await_receive(operation_id).await
}

async fn complete_circuit(
    context: GatewayClientContextV2,
    payment_hash: bitcoin::hashes::sha256::Hash,
    final_receive_state: FinalReceiveState,
    circuit: IncomingCircuitKey,
) -> Result<(), LightningRpcError> {
    let action = if let FinalReceiveState::Success(preimage) = final_receive_state {
        PaymentAction::Settle(Preimage(preimage))
    } else {
        PaymentAction::Cancel
    };
    let IncomingCircuitKey {
        incoming_chan_id,
        htlc_id,
    } = circuit;

    context
        .gateway
        .complete_htlc(InterceptPaymentResponse {
            incoming_chan_id,
            htlc_id,
            payment_hash,
            action,
        })
        .await
}

async fn log_completion(
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    client_ctx: GatewayClientContextV2,
    payment_hash: bitcoin::hashes::sha256::Hash,
) {
    client_ctx
        .module
        .client_ctx
        .log_event(
            &mut dbtx.module_tx(),
            CompleteLightningPaymentSucceeded {
                payment_image: PaymentImage::Hash(payment_hash),
            },
        )
        .await;
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum CompletionOutcome {
    Succeeded,
    Failed(String),
}

pub(super) fn completion_outcome(result: Result<(), LightningRpcError>) -> CompletionOutcome {
    match result {
        Ok(()) => CompletionOutcome::Succeeded,
        Err(error) => CompletionOutcome::Failed(error.to_string()),
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum CompleteSMState {
    Pending,
    Completing(FinalReceiveState),
    Completed,
    /// Lightning reached an incompatible permanent terminal outcome.
    CompletionFailed(String),
}

impl fmt::Display for CompleteSMState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompleteSMState::Pending => write!(f, "Pending"),
            CompleteSMState::Completing(_) => write!(f, "Completing"),
            CompleteSMState::Completed => write!(f, "Completed"),
            CompleteSMState::CompletionFailed(_) => write!(f, "Completion Failed"),
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
                await_receive(context.clone(), self.common.operation_id),
                |_, result, old_state| {
                    Box::pin(async move { Self::transition_receive(result, &old_state) })
                },
            )],
            CompleteSMState::Completing(finale_receive_state) => vec![StateTransition::new(
                complete_circuit(
                    gateway_context.clone(),
                    self.common.payment_hash,
                    finale_receive_state.clone(),
                    IncomingCircuitKey {
                        incoming_chan_id: self.common.incoming_chan_id,
                        htlc_id: self.common.htlc_id,
                    },
                ),
                move |dbtx, result, old_state| {
                    Box::pin(Self::transition_completion(
                        old_state,
                        dbtx,
                        gateway_context.clone(),
                        result,
                    ))
                },
            )],
            CompleteSMState::Completed | CompleteSMState::CompletionFailed(_) => Vec::new(),
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl fmt::Display for CircuitCompleteStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Circuit Complete State Machine Operation ID: {:?} State: {}",
            self.common.operation_id, self.state
        )
    }
}

impl CircuitCompleteStateMachine {
    fn update(&self, state: CompleteSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

impl State for CircuitCompleteStateMachine {
    type ModuleContext = GatewayClientContextV2;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gateway_context = context.clone();
        match &self.state {
            CompleteSMState::Pending => vec![StateTransition::new(
                await_receive(context.clone(), self.common.receive_operation_id),
                |_, result, old_state: CircuitCompleteStateMachine| {
                    Box::pin(async move { old_state.update(CompleteSMState::Completing(result)) })
                },
            )],
            CompleteSMState::Completing(final_receive_state) => vec![StateTransition::new(
                complete_circuit(
                    gateway_context.clone(),
                    self.common.payment_hash,
                    final_receive_state.clone(),
                    self.common.circuit,
                ),
                move |dbtx, result, old_state: CircuitCompleteStateMachine| {
                    let gateway_context = gateway_context.clone();
                    Box::pin(async move {
                        match completion_outcome(result) {
                            CompletionOutcome::Succeeded => {
                                log_completion(
                                    dbtx,
                                    gateway_context,
                                    old_state.common.payment_hash,
                                )
                                .await;
                                old_state.update(CompleteSMState::Completed)
                            }
                            CompletionOutcome::Failed(error) => {
                                old_state.update(CompleteSMState::CompletionFailed(error))
                            }
                        }
                    })
                },
            )],
            CompleteSMState::Completed | CompleteSMState::CompletionFailed(_) => Vec::new(),
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl CompleteStateMachine {
    fn transition_receive(
        final_receive_state: FinalReceiveState,
        old_state: &CompleteStateMachine,
    ) -> CompleteStateMachine {
        old_state.update(CompleteSMState::Completing(final_receive_state))
    }

    async fn transition_completion(
        old_state: CompleteStateMachine,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        client_ctx: GatewayClientContextV2,
        result: Result<(), LightningRpcError>,
    ) -> CompleteStateMachine {
        match completion_outcome(result) {
            CompletionOutcome::Succeeded => {
                log_completion(dbtx, client_ctx, old_state.common.payment_hash).await;
                old_state.update(CompleteSMState::Completed)
            }
            CompletionOutcome::Failed(error) => {
                old_state.update(CompleteSMState::CompletionFailed(error))
            }
        }
    }
}
