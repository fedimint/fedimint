use std::time::Duration;

use bitcoin::hashes::sha256;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientInputBundle};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::bitcoin_migration::{
    bitcoin30_to_bitcoin32_schnorr_signature, bitcoin32_to_bitcoin30_schnorr_signature,
};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::util::SafeUrl;
use fedimint_core::{secp256k1, OutPoint, TransactionId};
use fedimint_lnv2_common::contracts::OutgoingContract;
use fedimint_lnv2_common::{LightningInput, LightningInputV0, OutgoingWitness};
use secp256k1::schnorr::Signature;
use secp256k1::Keypair;
use tracing::error;

use crate::api::LightningFederationApi;
use crate::{LightningClientContext, LightningInvoice};

const RETRY_DELAY: Duration = Duration::from_secs(1);

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
    pub funding_txid: TransactionId,
    pub gateway_api: SafeUrl,
    pub contract: OutgoingContract,
    pub invoice: LightningInvoice,
    pub refund_keypair: Keypair,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum SendSMState {
    Funding,
    Funded,
    Rejected(String),
    Success([u8; 32]),
    Refunding(Vec<OutPoint>),
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that requests the lightning gateway to pay an invoice on
/// behalf of a federation client.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     Funding -- funding tx is rejected --> Rejected
///     Funding -- funding tx is accepted --> Funded
///     Funded -- post invoice returns preimage  --> Success
///     Funded -- post invoice returns forfeit tx --> Refunding
///     Funded -- await_preimage returns preimage --> Success
///     Funded -- await_preimage expires --> Refunding
/// ```
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
            SendSMState::Funding => {
                vec![StateTransition::new(
                    Self::await_funding(global_context.clone(), self.common.funding_txid),
                    |_, error, old_state| {
                        Box::pin(async move { Self::transition_funding(error, &old_state) })
                    },
                )]
            }
            SendSMState::Funded => {
                vec![
                    StateTransition::new(
                        Self::gateway_send_payment(
                            self.common.gateway_api.clone(),
                            context.federation_id,
                            self.common.contract.clone(),
                            self.common.invoice.clone(),
                            self.common.refund_keypair,
                            context.clone(),
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
                        Self::await_preimage(gc_preimage.clone(), self.common.contract.clone()),
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
            SendSMState::Refunding(..) | SendSMState::Success(..) | SendSMState::Rejected(..) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl SendStateMachine {
    async fn await_funding(
        global_context: DynGlobalClientContext,
        txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(txid).await
    }

    fn transition_funding(
        result: Result<(), String>,
        old_state: &SendStateMachine,
    ) -> SendStateMachine {
        old_state.update(match result {
            Ok(()) => SendSMState::Funded,
            Err(error) => SendSMState::Rejected(error),
        })
    }

    async fn gateway_send_payment(
        gateway_api: SafeUrl,
        federation_id: FederationId,
        contract: OutgoingContract,
        invoice: LightningInvoice,
        refund_keypair: Keypair,
        context: LightningClientContext,
    ) -> Result<[u8; 32], Signature> {
        loop {
            match context
                .gateway_conn
                .send_payment(
                    gateway_api.clone(),
                    federation_id,
                    contract.clone(),
                    invoice.clone(),
                    bitcoin32_to_bitcoin30_schnorr_signature(&refund_keypair.sign_schnorr(
                        secp256k1::Message::from_digest(
                            *invoice.consensus_hash::<sha256::Hash>().as_ref(),
                        ),
                    )),
                )
                .await
            {
                Ok(send_result) => {
                    if contract.verify_gateway_response(&send_result) {
                        return send_result.map_err(|signature| {
                            bitcoin30_to_bitcoin32_schnorr_signature(&signature)
                        });
                    }

                    error!(
                        ?send_result,
                        ?contract,
                        ?invoice,
                        ?federation_id,
                        ?gateway_api,
                        "Invalid gateway response"
                    );
                }
                Err(error) => {
                    error!(
                        ?error,
                        ?contract,
                        ?invoice,
                        ?federation_id,
                        ?gateway_api,
                        "Error while trying to send payment via gateway"
                    );
                }
            }

            sleep(RETRY_DELAY).await;
        }
    }

    async fn transition_gateway_send_payment(
        global_context: DynGlobalClientContext,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        gateway_response: Result<[u8; 32], Signature>,
        old_state: SendStateMachine,
    ) -> SendStateMachine {
        match gateway_response {
            Ok(preimage) => old_state.update(SendSMState::Success(preimage)),
            Err(signature) => {
                let client_input = ClientInput::<LightningInput> {
                    input: LightningInput::V0(LightningInputV0::Outgoing(
                        old_state.common.contract.contract_id(),
                        OutgoingWitness::Cancel(signature),
                    )),
                    amount: old_state.common.contract.amount,
                    keys: vec![old_state.common.refund_keypair],
                };

                let outpoints = global_context
                    .claim_inputs(
                        dbtx,
                        // The input of the refund tx is managed by this state machine
                        ClientInputBundle::new_no_sm(vec![client_input]),
                    )
                    .await
                    .expect("Cannot claim input, additional funding needed")
                    .1;

                old_state.update(SendSMState::Refunding(outpoints))
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
                .await_preimage(&contract.contract_id(), contract.expiration)
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
            return old_state.update(SendSMState::Success(preimage));
        }

        let client_input = ClientInput::<LightningInput> {
            input: LightningInput::V0(LightningInputV0::Outgoing(
                old_state.common.contract.contract_id(),
                OutgoingWitness::Refund,
            )),
            amount: old_state.common.contract.amount,
            keys: vec![old_state.common.refund_keypair],
        };

        let outpoints = global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![client_input]))
            .await
            .expect("Cannot claim input, additional funding needed")
            .1;

        old_state.update(SendSMState::Refunding(outpoints))
    }
}
