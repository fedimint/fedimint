use std::sync::Arc;

use bitcoin_hashes::Hash;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::KeyPair;
use fedimint_core::{Amount, OutPoint};
use fedimint_ln_common::PrunedInvoice;
use fedimint_lnv2_client::LightningClientStateMachines;
use fedimint_lnv2_common::contracts::OutgoingContract;
use fedimint_lnv2_common::{LightningInput, LightningInputV0, OutgoingWitness};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};

use crate::gateway_lnrpc::PayInvoiceRequest;
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
    pub invoice: Bolt11Invoice,
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
    LightningRpcError(String),
    DirectSwapError(String),
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
        invoice: Bolt11Invoice,
        contract: OutgoingContract,
    ) -> Result<[u8; 32], Cancelled> {
        // The following three checks may fail in edge cases since they have inherent
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

        if lightning_context.lightning_public_key == invoice.recover_payee_pub_key() {
            let invoice_msats = invoice
                .amount_milli_satoshis()
                .expect("We checked this previously");

            let (payload, client) = context
                .gateway
                .get_payload_and_client_v2(invoice.payment_hash().to_byte_array(), invoice_msats)
                .await
                .map_err(|e| Cancelled::DirectSwapError(e.to_string()))?;

            return client
                .get_first_module::<GatewayClientModuleV2>()
                .relay_direct_swap(payload)
                .await
                .map_err(|e| Cancelled::DirectSwapError(e.to_string()));
        }

        let max_fee = contract.amount - min_contract_amount;

        if lightning_context.lnrpc.supports_private_payments() {
            lightning_context
                .lnrpc
                .pay_private(
                    PrunedInvoice::try_from(invoice).expect("Invoice has amount"),
                    max_delay,
                    max_fee,
                )
                .await
        } else {
            lightning_context
                .lnrpc
                .pay(PayInvoiceRequest {
                    invoice: invoice.to_string(),
                    max_delay,
                    max_fee_msat: max_fee.msats,
                    payment_hash: invoice.payment_hash().to_byte_array().to_vec(),
                })
                .await
        }
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
