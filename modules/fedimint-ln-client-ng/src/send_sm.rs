use std::sync::Arc;
use std::time::Duration;

use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::util::SafeUrl;
use fedimint_core::{OutPoint, TransactionId};
use fedimint_ln_common_ng::api::LnFederationApi;
use fedimint_ln_common_ng::contracts::OutgoingContract;
use fedimint_ln_common_ng::{LightningClientContext, LightningInput, OutgoingWitness, Witness};
use lightning_invoice::Bolt11Invoice;
use secp256k1::schnorr::Signature;
use secp256k1::KeyPair;
use tracing::error;

use crate::{LightningClientStateMachines, SendPaymentPayload};

const RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SendStateMachine {
    pub operation_id: OperationId,
    pub contract: OutgoingContract,
    pub state: SendSMState,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum SendSMState {
    Funding(Funding),
    Funded(Funded),
    Rejected(String),
    Success([u8; 32]),
    Refunding(Vec<OutPoint>),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct Funding {
    pub txid: TransactionId,
    pub gateway_api: SafeUrl,
    pub invoice: Bolt11Invoice,
    pub refund_keypair: KeyPair,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct Funded {
    pub gateway_api: SafeUrl,
    pub invoice: Bolt11Invoice,
    pub refund_keypair: KeyPair,
}

impl State for SendStateMachine {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc_pay = global_context.clone();
        let gc_preimage = global_context.clone();

        match &self.state {
            SendSMState::Funding(funding) => {
                vec![StateTransition::new(
                    Self::await_funding(global_context.clone(), funding.txid),
                    move |_, error, old_state| Box::pin(Self::transition_funding(error, old_state)),
                )]
            }
            SendSMState::Funded(funded) => {
                vec![
                    StateTransition::new(
                        Self::gateway_send_payment(
                            funded.clone().gateway_api,
                            context.federation_id,
                            self.contract.clone(),
                            funded.clone().invoice,
                        ),
                        move |dbtx, response, old_state| {
                            Box::pin(Self::transition_gateway_send_payment(
                                gc_pay.clone(),
                                dbtx,
                                response,
                                old_state,
                            ))
                        },
                    ),
                    StateTransition::new(
                        Self::await_preimage(gc_preimage.clone(), self.contract.clone()),
                        move |dbtx, preimage, old_state| {
                            Box::pin(Self::transition_preimage(
                                dbtx,
                                gc_preimage.clone(),
                                old_state,
                                preimage,
                            ))
                        },
                    ),
                ]
            }
            SendSMState::Refunding(..) => {
                vec![]
            }
            SendSMState::Success(..) => {
                vec![]
            }
            SendSMState::Rejected(..) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

impl SendStateMachine {
    async fn await_funding(
        global_context: DynGlobalClientContext,
        txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(txid).await
    }

    async fn transition_funding(
        result: Result<(), String>,
        old_state: SendStateMachine,
    ) -> SendStateMachine {
        let funding = match old_state.state {
            SendSMState::Funding(funding) => funding,
            _ => panic!("Unexpected prior state"),
        };

        SendStateMachine {
            operation_id: old_state.operation_id,
            contract: old_state.contract,
            state: match result {
                Ok(()) => SendSMState::Funded(Funded {
                    gateway_api: funding.gateway_api,
                    invoice: funding.invoice,
                    refund_keypair: funding.refund_keypair,
                }),
                Err(error) => SendSMState::Rejected(error),
            },
        }
    }

    async fn gateway_send_payment(
        gateway_api: SafeUrl,
        federation_id: FederationId,
        contract: OutgoingContract,
        invoice: Bolt11Invoice,
    ) -> Result<[u8; 32], Signature> {
        loop {
            match Self::try_gateway_send_payment(
                gateway_api.clone(),
                federation_id,
                contract.clone(),
                invoice.clone(),
            )
            .await
            {
                Ok(gateway_response) => match gateway_response {
                    Ok(gateway_response) => {
                        if contract.verify_gateway_response(&gateway_response) {
                            return gateway_response;
                        } else {
                            error!("Invalid gateway response: {gateway_response:?}");
                        }
                    }
                    Err(error) => {
                        error!("Gateway returned error: {error}")
                    }
                },
                Err(error) => {
                    error!("Error while trying to reach gateway: {error}");
                }
            }

            sleep(RETRY_DELAY).await;
        }
    }

    async fn try_gateway_send_payment(
        gateway_api: SafeUrl,
        federation_id: FederationId,
        contract: OutgoingContract,
        invoice: Bolt11Invoice,
    ) -> anyhow::Result<Result<Result<[u8; 32], Signature>, String>> {
        let result = reqwest::Client::new()
            .post(
                gateway_api
                    .join("send_payment")
                    .expect("'send_payment' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(&SendPaymentPayload {
                federation_id,
                contract,
                invoice,
            })
            .send()
            .await?
            .json::<Result<Result<[u8; 32], Signature>, String>>()
            .await?;

        Ok(result)
    }

    async fn transition_gateway_send_payment(
        global_context: DynGlobalClientContext,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        gateway_response: Result<[u8; 32], Signature>,
        old_state: SendStateMachine,
    ) -> SendStateMachine {
        let funded = match old_state.state {
            SendSMState::Funded(funded) => funded,
            _ => panic!("Unexpected prior state"),
        };

        match gateway_response {
            Ok(preimage) => SendStateMachine {
                operation_id: old_state.operation_id,
                contract: old_state.contract,
                state: SendSMState::Success(preimage),
            },
            Err(signature) => {
                let client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
                    input: LightningInput {
                        amount: old_state.contract.amount,
                        witness: Witness::Outgoing(
                            old_state.contract.contract_key(),
                            OutgoingWitness::Cancel(signature),
                        ),
                    },
                    keys: vec![funded.refund_keypair],
                    // The input of the refund tx is managed by this state machine
                    state_machines: Arc::new(|_, _| vec![]),
                };

                let out_points = global_context.claim_input(dbtx, client_input).await.1;

                SendStateMachine {
                    operation_id: old_state.operation_id,
                    contract: old_state.contract,
                    state: SendSMState::Refunding(out_points),
                }
            }
        }
    }

    async fn await_preimage(
        global_context: DynGlobalClientContext,
        contract: OutgoingContract,
    ) -> Option<[u8; 32]> {
        loop {
            let preimage = global_context
                .module_api()
                .await_preimage(&contract.contract_key().preimage_key(), contract.expiration)
                .await;

            match preimage {
                Some(preimage) => {
                    if contract.verify_preimage(&preimage) {
                        return Some(preimage);
                    }

                    error!("Federation returned invalid preimage {:?}", preimage);
                }
                None => return None,
            }

            sleep(RETRY_DELAY).await;
        }
    }

    async fn transition_preimage(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
        old_state: SendStateMachine,
        preimage: Option<[u8; 32]>,
    ) -> SendStateMachine {
        if let Some(preimage) = preimage {
            return SendStateMachine {
                operation_id: old_state.operation_id,
                contract: old_state.contract,
                state: SendSMState::Success(preimage),
            };
        }

        let funded = match old_state.state {
            SendSMState::Funded(funded) => funded,
            _ => panic!("Unexpected prior state"),
        };

        let client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
            input: LightningInput {
                amount: old_state.contract.amount,
                witness: Witness::Outgoing(
                    old_state.contract.contract_key(),
                    OutgoingWitness::Refund,
                ),
            },
            keys: vec![funded.refund_keypair],
            // The input of the refund tx is managed by this state machine
            state_machines: Arc::new(|_, _| vec![]),
        };

        let out_points = global_context.claim_input(dbtx, client_input).await.1;

        SendStateMachine {
            operation_id: old_state.operation_id,
            contract: old_state.contract,
            state: SendSMState::Refunding(out_points),
        }
    }
}
