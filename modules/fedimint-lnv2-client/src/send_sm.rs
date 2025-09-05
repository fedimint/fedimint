use anyhow::ensure;
use bitcoin::hashes::sha256;
use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_core::util::SafeUrl;
use fedimint_core::util::backoff_util::api_networking_backoff;
use fedimint_core::{OutPoint, TransactionId, crit, secp256k1, util};
use fedimint_lnv2_common::contracts::OutgoingContract;
use fedimint_lnv2_common::{LightningInput, LightningInputV0, OutgoingWitness};
use fedimint_logging::LOG_CLIENT_MODULE_LNV2;
use futures::future::pending;
use secp256k1::Keypair;
use secp256k1::schnorr::Signature;
use tracing::instrument;

use crate::api::LightningFederationApi;
use crate::{LightningClientContext, LightningInvoice};

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
    pub outpoint: OutPoint,
    pub contract: OutgoingContract,
    pub gateway_api: Option<SafeUrl>,
    pub invoice: Option<LightningInvoice>,
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
                    Self::await_funding(global_context.clone(), self.common.outpoint.txid),
                    |_, error, old_state| {
                        Box::pin(async move { Self::transition_funding(error, &old_state) })
                    },
                )]
            }
            SendSMState::Funded => {
                vec![
                    StateTransition::new(
                        Self::gateway_send_payment(
                            self.common.gateway_api.clone().unwrap(),
                            context.federation_id,
                            self.common.outpoint,
                            self.common.contract.clone(),
                            self.common.invoice.clone().unwrap(),
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
                        Self::await_preimage(
                            self.common.outpoint,
                            self.common.contract.clone(),
                            gc_preimage.clone(),
                        ),
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

    #[instrument(target = LOG_CLIENT_MODULE_LNV2, skip(refund_keypair, context))]
    async fn gateway_send_payment(
        gateway_api: SafeUrl,
        federation_id: FederationId,
        outpoint: OutPoint,
        contract: OutgoingContract,
        invoice: LightningInvoice,
        refund_keypair: Keypair,
        context: LightningClientContext,
    ) -> Result<[u8; 32], Signature> {
        util::retry("gateway-send-payment", api_networking_backoff(), || async {
            let payment_result = context
                .gateway_conn
                .send_payment(
                    gateway_api.clone(),
                    federation_id,
                    outpoint,
                    contract.clone(),
                    invoice.clone(),
                    refund_keypair.sign_schnorr(secp256k1::Message::from_digest(
                        *invoice.consensus_hash::<sha256::Hash>().as_ref(),
                    )),
                )
                .await?;

            ensure!(
                contract.verify_gateway_response(&payment_result),
                "Invalid gateway response: {payment_result:?}"
            );

            Ok(payment_result)
        })
        .await
        .expect("Number of retries has no limit")
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
                        old_state.common.outpoint,
                        OutgoingWitness::Cancel(signature),
                    )),
                    amounts: Amounts::new_bitcoin(old_state.common.contract.amount),
                    keys: vec![old_state.common.refund_keypair],
                };

                let change_range = global_context
                    .claim_inputs(
                        dbtx,
                        // The input of the refund tx is managed by this state machine
                        ClientInputBundle::new_no_sm(vec![client_input]),
                    )
                    .await
                    .expect("Cannot claim input, additional funding needed");

                old_state.update(SendSMState::Refunding(change_range.into_iter().collect()))
            }
        }
    }

    #[instrument(target = LOG_CLIENT_MODULE_LNV2, skip(global_context))]
    async fn await_preimage(
        outpoint: OutPoint,
        contract: OutgoingContract,
        global_context: DynGlobalClientContext,
    ) -> Option<[u8; 32]> {
        let preimage = global_context
            .module_api()
            .await_preimage(outpoint, contract.expiration)
            .await?;

        if contract.verify_preimage(&preimage) {
            return Some(preimage);
        }

        crit!(target: LOG_CLIENT_MODULE_LNV2, "Federation returned invalid preimage {:?}", preimage);

        pending().await
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
                old_state.common.outpoint,
                OutgoingWitness::Refund,
            )),
            amounts: Amounts::new_bitcoin(old_state.common.contract.amount),
            keys: vec![old_state.common.refund_keypair],
        };

        let change_range = global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![client_input]))
            .await
            .expect("Cannot claim input, additional funding needed");

        old_state.update(SendSMState::Refunding(change_range.into_iter().collect()))
    }
}
