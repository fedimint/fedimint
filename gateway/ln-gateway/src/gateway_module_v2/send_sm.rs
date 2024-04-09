use std::sync::Arc;

use bitcoin_hashes::Hash;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::{KeyPair, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint};
use fedimint_lnv2_client::LightningClientStateMachines;
use fedimint_lnv2_common::contracts::OutgoingContract;
use fedimint_lnv2_common::{LightningInput, OutgoingWitness, Witness};
use lightning_invoice::Bolt11Invoice;

use crate::gateway_lnrpc::PayInvoiceRequest;
use crate::gateway_module_v2::GatewayClientContextV2;

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
    pub max_fee_msat: u64,
    pub invoice: Bolt11Invoice,
    pub claim_keypair: KeyPair,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum SendSMState {
    Sending,
    Claiming(Claiming),
    Cancelled(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct Claiming {
    pub preimage: [u8; 32],
    pub outpoints: Vec<OutPoint>,
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
                        self.common.max_fee_msat,
                        self.common.invoice.clone(),
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
            SendSMState::Claiming(..) => {
                vec![]
            }
            SendSMState::Cancelled(..) => {
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
        max_fee_msat: u64,
        invoice: Bolt11Invoice,
    ) -> Result<[u8; 32], String> {
        let lightning_context = context
            .gateway
            .get_lightning_context()
            .await
            .map_err(|e| e.to_string())?;

        if lightning_context.lightning_public_key == invoice.recover_payee_pub_key() {
            let invoice_msats = invoice
                .amount_milli_satoshis()
                .expect("We checked this previously");

            return context
                .gateway
                .receive_v2(
                    invoice.payment_hash().into_inner(),
                    Amount::from_msats(invoice_msats),
                )
                .await
                .map_err(|e| e.to_string());
        }

        lightning_context
            .lnrpc
            .pay(PayInvoiceRequest {
                invoice: invoice.to_string(),
                max_delay,
                max_fee_msat,
                payment_hash: invoice.payment_hash().to_vec(),
            })
            .await
            .map(|response| {
                response
                    .preimage
                    .as_slice()
                    .try_into()
                    .expect("Preimage is 32 bytes")
            })
            .map_err(|e| e.to_string())
    }

    async fn transition_send_payment(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: SendStateMachine,
        global_context: DynGlobalClientContext,
        result: Result<[u8; 32], String>,
    ) -> SendStateMachine {
        match result {
            Ok(preimage) => {
                let client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
                    input: LightningInput {
                        amount: old_state.common.contract.amount,
                        witness: Witness::Outgoing(
                            old_state.common.contract.contract_id(),
                            OutgoingWitness::Claim(preimage),
                        ),
                    },
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
