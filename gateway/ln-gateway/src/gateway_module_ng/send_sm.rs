use std::sync::Arc;

use bitcoin_hashes::Hash;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::{KeyPair, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::{Amount, OutPoint};
use fedimint_ln_client_ng::LightningClientStateMachines;
use fedimint_ln_common_ng::contracts::OutgoingContract;
use fedimint_ln_common_ng::{LightningInput, OutgoingWitness, Witness};
use lightning_invoice::Bolt11Invoice;
use secp256k1::SecretKey;
use tracing::error;

use crate::gateway_lnrpc::PayInvoiceRequest;
use crate::gateway_module_ng::GatewayClientContextNG;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SendStateMachine {
    pub operation_id: OperationId,
    pub contract: OutgoingContract,
    pub state: SendSMState,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum SendSMState {
    Sending(Sending),
    Claiming([u8; 32], Vec<OutPoint>),
    Cancelled,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct Sending {
    pub max_delay: u64,
    pub max_fee_msat: u64,
    pub invoice: Bolt11Invoice,
    pub claim_keypair: KeyPair,
}

impl State for SendStateMachine {
    type ModuleContext = GatewayClientContextNG;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();

        match &self.state {
            SendSMState::Sending(sending) => {
                vec![StateTransition::new(
                    Self::send_payment(
                        context.clone(),
                        sending.max_delay,
                        sending.max_fee_msat,
                        sending.invoice.clone(),
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
            SendSMState::Cancelled => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

impl SendStateMachine {
    async fn send_payment(
        context: GatewayClientContextNG,
        max_delay: u64,
        max_fee_msat: u64,
        invoice: Bolt11Invoice,
    ) -> Result<[u8; 32], ()> {
        let pk = SecretKey::from_slice(&[42; 32])
            .expect("32 bytes, within curve order")
            .public_key(secp256k1::SECP256K1);

        let invoice_msats = invoice
            .amount_milli_satoshis()
            .expect("We checked this previously");

        if pk == invoice.recover_payee_pub_key() {
            return match context
                .gateway
                .receive(
                    invoice.payment_hash().into_inner(),
                    Amount::from_msats(invoice_msats),
                )
                .await
            {
                Ok(preimage) => Ok(preimage),
                Err(e) => {
                    error!("Failed to route internal payment {:?}", e);

                    Err(())
                }
            };
        }

        let lightning_context = loop {
            match context.gateway.get_lightning_context().await {
                Ok(lightning_context) => break lightning_context,
                Err(_) => {
                    sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        };

        match lightning_context
            .lnrpc
            .pay(PayInvoiceRequest {
                invoice: invoice.to_string(),
                max_delay,
                max_fee_msat,
                payment_hash: invoice.payment_hash().to_vec(),
            })
            .await
        {
            Ok(response) => Ok(response
                .preimage
                .as_slice()
                .try_into()
                .expect("Preimage is 32 bytes")),
            Err(..) => Err(()),
        }
    }

    async fn transition_send_payment(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: SendStateMachine,
        global_context: DynGlobalClientContext,
        result: Result<[u8; 32], ()>,
    ) -> SendStateMachine {
        let sending = match old_state.state {
            SendSMState::Sending(sending) => sending,
            _ => panic!("Invalid prior state"),
        };

        match result {
            Ok(preimage) => {
                let client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
                    input: LightningInput {
                        amount: old_state.contract.amount,
                        witness: Witness::Outgoing(
                            old_state.contract.contract_key(),
                            OutgoingWitness::Claim(preimage),
                        ),
                    },
                    keys: vec![sending.claim_keypair],
                    state_machines: Arc::new(|_, _| vec![]),
                };

                let out_points = global_context.claim_input(dbtx, client_input).await.1;

                SendStateMachine {
                    operation_id: old_state.operation_id,
                    contract: old_state.contract.clone(),
                    state: SendSMState::Claiming(preimage, out_points),
                }
            }
            Err(()) => SendStateMachine {
                operation_id: old_state.operation_id,
                contract: old_state.contract.clone(),
                state: SendSMState::Cancelled,
            },
        }
    }
}
