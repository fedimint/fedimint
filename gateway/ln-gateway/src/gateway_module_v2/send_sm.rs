use std::sync::Arc;

use bitcoin_hashes::Hash;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::KeyPair;
use fedimint_core::{Amount, OutPoint};
use fedimint_lnv2_client::{LightningClientStateMachines, LightningInvoice};
use fedimint_lnv2_common::contracts::OutgoingContract;
use fedimint_lnv2_common::{LightningInput, LightningInputV0, OutgoingWitness};
use serde::{Deserialize, Serialize};

use super::FinalReceiveState;
use crate::gateway_module_v2::{GatewayClientContextV2, GatewayClientModuleV2};

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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SendSMCommon {
    pub operation_id: OperationId,
    pub contract: OutgoingContract,
    pub max_delay: u64,
    pub min_contract_amount: Amount,
    pub invoice: LightningInvoice,
    pub claim_keypair: KeyPair,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum SendSMState {
    Sending,
    Claiming(Claiming),
    Cancelled(Cancelled),
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

        match &self.state {
            SendSMState::Sending => {
                vec![StateTransition::new(
                    Self::send_payment(
                        context.clone(),
                        self.common.max_delay,
                        self.common.min_contract_amount,
                        self.common.invoice.clone(),
                        self.common.contract.clone(),
                    ),
                    move |dbtx, result, old_state| {
                        Box::pin(Self::transition_send_payment(
                            dbtx,
                            old_state,
                            gc.clone(),
                            result,
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
        max_delay: u64,
        min_contract_amount: Amount,
        invoice: LightningInvoice,
        contract: OutgoingContract,
    ) -> Result<[u8; 32], Cancelled> {
        let LightningInvoice::Bolt11(invoice) = invoice;

        // The following two checks may fail in edge cases since they have inherent
        // timing assumptions. Therefore, they may only be checked after we have created
        // the state machine such that we can cancel the contract.
        if invoice.is_expired() {
            return Err(Cancelled::InvoiceExpired);
        }

        if max_delay == 0 {
            return Err(Cancelled::TimeoutTooClose);
        }

        if contract.amount < min_contract_amount {
            return Err(Cancelled::Underfunded);
        }

        let lightning_context = context
            .gateway
            .get_lightning_context()
            .await
            .map_err(|e| Cancelled::LightningRpcError(e.to_string()))?;

        if lightning_context.lightning_public_key == invoice.get_payee_pub_key() {
            let (contract, client) = context
                .gateway
                .get_registered_incoming_contract_and_client_v2(
                    invoice.payment_hash().to_byte_array(),
                    invoice
                        .amount_milli_satoshis()
                        .expect("The amount invoice has been checked previously"),
                )
                .await
                .map_err(|e| Cancelled::RegistrationError(e.to_string()))?;

            return match client
                .get_first_module::<GatewayClientModuleV2>()
                .relay_direct_swap(contract)
                .await
            {
                Ok(final_receive_state) => match final_receive_state {
                    FinalReceiveState::Rejected => Err(Cancelled::Rejected),
                    FinalReceiveState::Success(preimage) => Ok(preimage),
                    FinalReceiveState::Refunded => Err(Cancelled::Refunded),
                    FinalReceiveState::Failure => Err(Cancelled::Failure),
                },
                Err(e) => Err(Cancelled::FinalizationError(e.to_string())),
            };
        }

        lightning_context
            .lnrpc
            .pay(invoice, max_delay, contract.amount - min_contract_amount)
            .await
            .map(|response| {
                response
                    .preimage
                    .as_slice()
                    .try_into()
                    .expect("Preimage is 32 bytes")
            })
            .map_err(|e| Cancelled::LightningRpcError(e.to_string()))
    }

    async fn transition_send_payment(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: SendStateMachine,
        global_context: DynGlobalClientContext,
        result: Result<[u8; 32], Cancelled>,
    ) -> SendStateMachine {
        match result {
            Ok(preimage) => {
                let client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
                    input: LightningInput::V0(LightningInputV0::Outgoing(
                        old_state.common.contract.contract_id(),
                        OutgoingWitness::Claim(preimage),
                    )),
                    amount: old_state.common.contract.amount,
                    keys: vec![old_state.common.claim_keypair],
                    state_machines: Arc::new(|_, _| vec![]),
                };

                let outpoints = global_context.claim_input(dbtx, client_input).await.1;

                old_state.update(SendSMState::Claiming(Claiming {
                    preimage,
                    outpoints,
                }))
            }
            Err(e) => old_state.update(SendSMState::Cancelled(e)),
        }
    }
}
