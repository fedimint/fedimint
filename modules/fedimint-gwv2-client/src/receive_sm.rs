use core::fmt;
use std::collections::BTreeMap;

use anyhow::anyhow;
use fedimint_api_client::api::{FederationApiExt, ServerError};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{Amounts, ApiRequestErased};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::{NumPeersExt, OutPoint, PeerId};
use fedimint_lnv2_common::contracts::{IncomingContract, LightningContract};
use fedimint_lnv2_common::endpoint_constants::DECRYPTION_KEY_SHARE_ENDPOINT;
use fedimint_lnv2_common::{LightningInput, LightningInputV0};
use fedimint_logging::LOG_CLIENT_MODULE_GW;
use tpe::{AggregatePublicKey, DecryptionKeyShare, PublicKeyShare, aggregate_dk_shares};
use tracing::warn;

use super::events::{IncomingPaymentFailed, IncomingPaymentSucceeded};
use crate::GatewayClientContextV2;
use crate::db::OutpointContractKey;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct ReceiveStateMachine {
    pub common: ReceiveSMCommon,
    pub state: ReceiveSMState,
}

impl ReceiveStateMachine {
    pub fn update(&self, state: ReceiveSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

impl fmt::Display for ReceiveStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Receive State Machine Operation ID: {:?} State: {}",
            self.common.operation_id, self.state
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct ReceiveSMCommon {
    pub operation_id: OperationId,
    pub contract: IncomingContract,
    pub outpoint: OutPoint,
    pub refund_keypair: Keypair,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum ReceiveSMState {
    Funding,
    Rejected(String),
    Success([u8; 32]),
    Failure,
    Refunding(Vec<OutPoint>),
}

impl fmt::Display for ReceiveSMState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiveSMState::Funding => write!(f, "Funding"),
            ReceiveSMState::Rejected(_) => write!(f, "Rejected"),
            ReceiveSMState::Success(_) => write!(f, "Success"),
            ReceiveSMState::Failure => write!(f, "Failure"),
            ReceiveSMState::Refunding(_) => write!(f, "Refunding"),
        }
    }
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that handles the relay of an incoming Lightning payment.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     Funding -- funding transaction is rejected --> Rejected
///     Funding -- aggregated decryption key is invalid --> Failure
///     Funding -- decrypted preimage is valid --> Success
///     Funding -- decrypted preimage is invalid --> Refunding
/// ```
impl State for ReceiveStateMachine {
    type ModuleContext = GatewayClientContextV2;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();
        let tpe_agg_pk = context.tpe_agg_pk;
        let gateway_context_ready = context.clone();

        match &self.state {
            ReceiveSMState::Funding => {
                vec![StateTransition::new(
                    Self::await_decryption_shares(
                        global_context.clone(),
                        context.tpe_pks.clone(),
                        self.common.outpoint,
                        self.common.contract.clone(),
                    ),
                    move |dbtx, output_outcomes, old_state| {
                        Box::pin(Self::transition_decryption_shares(
                            dbtx,
                            output_outcomes,
                            old_state,
                            gc.clone(),
                            tpe_agg_pk,
                            gateway_context_ready.clone(),
                        ))
                    },
                )]
            }
            ReceiveSMState::Success(..)
            | ReceiveSMState::Rejected(..)
            | ReceiveSMState::Refunding(..)
            | ReceiveSMState::Failure => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl ReceiveStateMachine {
    async fn await_decryption_shares(
        global_context: DynGlobalClientContext,
        tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
        outpoint: OutPoint,
        contract: IncomingContract,
    ) -> Result<BTreeMap<PeerId, DecryptionKeyShare>, String> {
        global_context.await_tx_accepted(outpoint.txid).await?;

        Ok(global_context
            .module_api()
            .request_with_strategy_retry(
                FilterMapThreshold::new(
                    move |peer_id, share: DecryptionKeyShare| {
                        if !contract.verify_decryption_share(
                            tpe_pks
                                .get(&peer_id)
                                .ok_or(ServerError::InternalClientError(anyhow!(
                                    "Missing TPE PK for peer {peer_id}?!"
                                )))?,
                            &share,
                        ) {
                            return Err(fedimint_api_client::api::ServerError::InvalidResponse(
                                anyhow!("Invalid decryption share"),
                            ));
                        }

                        Ok(share)
                    },
                    global_context.api().all_peers().to_num_peers(),
                ),
                DECRYPTION_KEY_SHARE_ENDPOINT.to_owned(),
                ApiRequestErased::new(outpoint),
            )
            .await)
    }

    async fn transition_decryption_shares(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        decryption_shares: Result<BTreeMap<PeerId, DecryptionKeyShare>, String>,
        old_state: ReceiveStateMachine,
        global_context: DynGlobalClientContext,
        tpe_agg_pk: AggregatePublicKey,
        client_ctx: GatewayClientContextV2,
    ) -> ReceiveStateMachine {
        let decryption_shares = match decryption_shares {
            Ok(decryption_shares) => decryption_shares
                .into_iter()
                .map(|(peer, share)| (peer.to_usize() as u64, share))
                .collect(),
            Err(error) => {
                client_ctx
                    .module
                    .client_ctx
                    .log_event(
                        &mut dbtx.module_tx(),
                        IncomingPaymentFailed {
                            payment_image: old_state
                                .common
                                .contract
                                .commitment
                                .payment_image
                                .clone(),
                            error: error.clone(),
                        },
                    )
                    .await;

                return old_state.update(ReceiveSMState::Rejected(error));
            }
        };

        let agg_decryption_key = aggregate_dk_shares(&decryption_shares);

        if !old_state
            .common
            .contract
            .verify_agg_decryption_key(&tpe_agg_pk, &agg_decryption_key)
        {
            warn!(target: LOG_CLIENT_MODULE_GW, "Failed to obtain decryption key. Client config's public keys are inconsistent");

            client_ctx
                .module
                .client_ctx
                .log_event(
                    &mut dbtx.module_tx(),
                    IncomingPaymentFailed {
                        payment_image: old_state.common.contract.commitment.payment_image.clone(),
                        error: "Client config's public keys are inconsistent".to_string(),
                    },
                )
                .await;

            return old_state.update(ReceiveSMState::Failure);
        }

        if let Some(preimage) = old_state
            .common
            .contract
            .decrypt_preimage(&agg_decryption_key)
        {
            client_ctx
                .module
                .client_ctx
                .log_event(
                    &mut dbtx.module_tx(),
                    IncomingPaymentSucceeded {
                        payment_image: old_state.common.contract.commitment.payment_image.clone(),
                    },
                )
                .await;

            return old_state.update(ReceiveSMState::Success(preimage));
        }

        // Store the contract for later amount lookup
        dbtx.module_tx()
            .insert_entry(
                &OutpointContractKey(old_state.common.outpoint),
                &LightningContract::Incoming(old_state.common.contract.clone()),
            )
            .await;

        let client_input = ClientInput::<LightningInput> {
            input: LightningInput::V0(LightningInputV0::Incoming(
                old_state.common.outpoint,
                agg_decryption_key,
            )),
            amounts: Amounts::new_bitcoin(old_state.common.contract.commitment.amount),
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
            .into_iter()
            .collect();

        client_ctx
            .module
            .client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                IncomingPaymentFailed {
                    payment_image: old_state.common.contract.commitment.payment_image.clone(),
                    error: "Failed to decrypt preimage".to_string(),
                },
            )
            .await;

        old_state.update(ReceiveSMState::Refunding(outpoints))
    }
}
