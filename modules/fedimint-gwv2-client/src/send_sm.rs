use std::fmt;

use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_core::secp256k1::Keypair;
use fedimint_core::{Amount, OutPoint};
use fedimint_lnv2_common::contracts::OutgoingContract;
use fedimint_lnv2_common::{LightningInput, LightningInputV0, LightningInvoice, OutgoingWitness};
use serde::{Deserialize, Serialize};

use super::FinalReceiveState;
use super::events::{OutgoingPaymentFailed, OutgoingPaymentSucceeded};
use crate::{GatewayClientContextV2, GatewayClientModuleV2};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SendStateMachine {
    pub common: SendSMCommon,
    pub state: SendSMState,
}

impl SendStateMachine {
    pub fn update(&self, state: SendSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

impl fmt::Display for SendStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Send State Machine Operation ID: {:?} State: {}",
            self.common.operation_id, self.state
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SendSMCommon {
    pub operation_id: OperationId,
    pub outpoint: OutPoint,
    pub contract: OutgoingContract,
    pub max_delay: u64,
    pub min_contract_amount: Amount,
    pub invoice: LightningInvoice,
    pub claim_keypair: Keypair,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum SendSMState {
    Sending,
    Claiming(Claiming),
    Cancelled(Cancelled),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentResponse {
    preimage: [u8; 32],
    target_federation: Option<FederationId>,
}

impl fmt::Display for SendSMState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendSMState::Sending => write!(f, "Sending"),
            SendSMState::Claiming(_) => write!(f, "Claiming"),
            SendSMState::Cancelled(_) => write!(f, "Cancelled"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct Claiming {
    pub preimage: [u8; 32],
    pub outpoints: Vec<OutPoint>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub enum Cancelled {
    InvoiceExpired,
    TimeoutTooClose,
    Underfunded,
    RegistrationError(String),
    FinalizationError(String),
    Rejected,
    Refunded,
    Failure,
    LightningRpcError(String),
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that handles the relay of an incoming Lightning payment.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     Sending -- payment is successful --> Claiming
///     Sending -- payment fails --> Cancelled
/// ```
impl State for SendStateMachine {
    type ModuleContext = GatewayClientContextV2;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();
        let gateway_context = context.clone();

        match &self.state {
            SendSMState::Sending => {
                vec![StateTransition::new(
                    Self::send_payment(context.clone(), self.common.clone()),
                    move |dbtx, result, old_state| {
                        Box::pin(Self::transition_send_payment(
                            dbtx,
                            old_state,
                            gc.clone(),
                            result,
                            gateway_context.clone(),
                        ))
                    },
                )]
            }
            SendSMState::Claiming(..) | SendSMState::Cancelled(..) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl SendStateMachine {
    async fn send_payment(
        context: GatewayClientContextV2,
        common: SendSMCommon,
    ) -> Result<PaymentResponse, Cancelled> {
        let SendSMCommon {
            operation_id: _,
            outpoint,
            contract,
            max_delay,
            min_contract_amount,
            invoice,
            claim_keypair: _,
        } = common;
        let LightningInvoice::Bolt11(invoice) = invoice;

        // `max_delay` is computed once when the state machine is created and
        // persisted, so this check cannot drift across a restart. It guards
        // every rail, not just Lightning: after paying out, a swap races the
        // outgoing contract's expiration to claim it, the same race an HTLC
        // runs against the contract timelock.
        if max_delay == 0 {
            return Err(Cancelled::TimeoutTooClose);
        }

        let Some(max_fee) = contract.amount.checked_sub(min_contract_amount) else {
            return Err(Cancelled::Underfunded);
        };

        // The persisted `max_delay` was measured against the contract's
        // remaining blocks when the send was accepted. A dispatch that happens
        // later, after a restart or while waiting for the lightning node, must
        // not spend blocks that have since passed: an HTLC whose timelock
        // outlives the contract lets the payee settle after the gateway can no
        // longer claim. So the budget for a fresh dispatch is measured again,
        // waiting for the federation to answer. Every rail below needs the
        // lightning node, so wait for it first: a budget measured before an
        // outage would go stale for as long as the outage lasts.
        context.gateway.await_lightning_connected().await;
        let fresh_max_delay = context
            .module
            .await_outgoing_contract_max_delay(outpoint)
            .await;

        // Invoice expiry and the fresh budget, by contrast with the checks
        // above, change over time, and this state machine re-runs from scratch
        // on every restart: either can run out while a payment dispatched
        // before a crash is still in flight, and that payment settles or fails
        // regardless. Cancelling on them alone would forfeit a contract the
        // in-flight payment can still claim. Each rail below therefore resumes
        // anything it already started unconditionally and consults this
        // verdict only before dispatching fresh.
        let fresh_dispatch_refusal = fresh_dispatch_refusal(invoice.is_expired(), fresh_max_delay);

        // To make gateway operation easier, we check if the invoice was created using
        // the LNv1 protocol and if the gateway supports the target federation.
        // If it does, we can fund an LNv1 incoming contract to satisfy the LNv2
        // outgoing payment.
        if let Some(client) = context.gateway.is_lnv1_invoice(&invoice).await {
            let final_state = context
                .gateway
                .relay_lnv1_swap(client.value(), &invoice, fresh_dispatch_refusal.is_none())
                .await;
            return match final_state {
                Ok(Some(final_receive_state)) => match final_receive_state {
                    FinalReceiveState::Rejected => Err(Cancelled::Rejected),
                    FinalReceiveState::Success(preimage) => Ok(PaymentResponse {
                        preimage,
                        target_federation: Some(client.value().federation_id()),
                    }),
                    FinalReceiveState::Refunded => Err(Cancelled::Refunded),
                    FinalReceiveState::Failure => Err(Cancelled::Failure),
                },
                Ok(None) => Err(fresh_dispatch_refusal
                    .expect("the relay only refuses a fresh dispatch when one was denied")),
                Err(e) => Err(Cancelled::FinalizationError(e.to_string())),
            };
        }

        match context
            .gateway
            .is_direct_swap(&invoice)
            .await
            .map_err(|e| Cancelled::RegistrationError(e.to_string()))?
        {
            Some((contract, client)) => {
                match client
                    .get_first_module::<GatewayClientModuleV2>()
                    .expect("Must have client module")
                    .relay_direct_swap(
                        contract,
                        invoice
                            .amount_milli_satoshis()
                            .expect("amountless invoices are not supported"),
                        fresh_dispatch_refusal.is_none(),
                    )
                    .await
                {
                    Ok(Some(final_receive_state)) => match final_receive_state {
                        FinalReceiveState::Rejected => Err(Cancelled::Rejected),
                        FinalReceiveState::Success(preimage) => Ok(PaymentResponse {
                            preimage,
                            target_federation: Some(client.federation_id()),
                        }),
                        FinalReceiveState::Refunded => Err(Cancelled::Refunded),
                        FinalReceiveState::Failure => Err(Cancelled::Failure),
                    },
                    Ok(None) => Err(fresh_dispatch_refusal
                        .expect("the relay only refuses a fresh dispatch when one was denied")),
                    Err(e) => Err(Cancelled::FinalizationError(e.to_string())),
                }
            }
            None => {
                // A payment the node already knows resolves through `pay`'s
                // idempotent resume path, which ignores `max_delay`, so the
                // verdict only refuses a dispatch that never happened.
                if let Some(refusal) = fresh_dispatch_refusal
                    && !context
                        .gateway
                        .outbound_payment_exists(*invoice.payment_hash())
                        .await
                {
                    return Err(refusal);
                }

                let preimage = context
                    .gateway
                    .pay(invoice, fresh_max_delay, max_fee)
                    .await
                    .map_err(|e| Cancelled::LightningRpcError(e.to_string()))?;
                Ok(PaymentResponse {
                    preimage,
                    target_federation: None,
                })
            }
        }
    }

    async fn transition_send_payment(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: SendStateMachine,
        global_context: DynGlobalClientContext,
        result: Result<PaymentResponse, Cancelled>,
        client_ctx: GatewayClientContextV2,
    ) -> SendStateMachine {
        match result {
            Ok(payment_response) => {
                client_ctx
                    .module
                    .client_ctx
                    .log_event(
                        &mut dbtx.module_tx(),
                        OutgoingPaymentSucceeded {
                            payment_image: old_state.common.contract.payment_image.clone(),
                            target_federation: payment_response.target_federation,
                        },
                    )
                    .await;
                let client_input = ClientInput::<LightningInput> {
                    input: LightningInput::V0(LightningInputV0::Outgoing(
                        old_state.common.outpoint,
                        OutgoingWitness::Claim(payment_response.preimage),
                    )),
                    amounts: Amounts::new_bitcoin(old_state.common.contract.amount),
                    keys: vec![old_state.common.claim_keypair],
                };

                let outpoints = global_context
                    .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![client_input]))
                    .await
                    .expect("Cannot claim input, additional funding needed")
                    .into_iter()
                    .collect();

                old_state.update(SendSMState::Claiming(Claiming {
                    preimage: payment_response.preimage,
                    outpoints,
                }))
            }
            Err(e) => {
                client_ctx
                    .module
                    .client_ctx
                    .log_event(
                        &mut dbtx.module_tx(),
                        OutgoingPaymentFailed {
                            payment_image: old_state.common.contract.payment_image.clone(),
                            error: e.clone(),
                        },
                    )
                    .await;
                old_state.update(SendSMState::Cancelled(e))
            }
        }
    }
}

/// Decides whether a send may dispatch a payment it has not started yet,
/// returning the reason to cancel with if not. A payment already in flight
/// resumes regardless.
pub(crate) fn fresh_dispatch_refusal(
    invoice_expired: bool,
    fresh_max_delay: u64,
) -> Option<Cancelled> {
    if invoice_expired {
        Some(Cancelled::InvoiceExpired)
    } else if fresh_max_delay == 0 {
        Some(Cancelled::TimeoutTooClose)
    } else {
        None
    }
}
