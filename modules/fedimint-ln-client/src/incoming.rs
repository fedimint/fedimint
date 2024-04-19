//! # Incoming State Machine
//!
//! This shared state machine is used by clients
//! that want to pay other clients within the federation
//!
//! It's applied in two places:
//!   - `fedimint-ln-client` for internal payments without involving the gateway
//!   - `gateway` for receiving payments into the federation

use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::sha256;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::runtime::sleep;
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_ln_common::contracts::incoming::IncomingContractAccount;
use fedimint_ln_common::contracts::{ContractId, Preimage};
use fedimint_ln_common::{LightningInput, LightningOutputOutcome};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::api::LnFederationApi;
use crate::{set_payment_result, LightningClientContext, PayType};

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that executes a transaction between two users
/// within a federation. This creates and funds an incoming contract
/// based on an existing offer within the federation.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    FundingOffer -- funded incoming contract --> DecryptingPreimage
///    FundingOffer -- funding incoming contract failed --> FundingFailed
///    DecryptingPreimage -- successfully decrypted preimage --> Preimage
///    DecryptingPreimage -- invalid preimage --> RefundSubmitted
///    DecryptingPreimage -- error decrypting preimage --> Failure
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum IncomingSmStates {
    FundingOffer(FundingOfferState),
    DecryptingPreimage(DecryptingPreimageState),
    Preimage(Preimage),
    RefundSubmitted {
        out_points: Vec<OutPoint>,
        error: IncomingSmError,
    },
    FundingFailed {
        error: IncomingSmError,
    },
    Failure(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct IncomingSmCommon {
    pub operation_id: OperationId,
    pub contract_id: ContractId,
    pub payment_hash: sha256::Hash,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct IncomingStateMachine {
    pub common: IncomingSmCommon,
    pub state: IncomingSmStates,
}

impl State for IncomingStateMachine {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        match &self.state {
            IncomingSmStates::FundingOffer(state) => state.transitions(global_context, context),
            IncomingSmStates::DecryptingPreimage(state) => {
                state.transitions(&self.common, global_context, context)
            }
            _ => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> fedimint_core::core::OperationId {
        self.common.operation_id
    }
}

#[derive(
    Error, Debug, Serialize, Deserialize, Encodable, Decodable, Hash, Clone, Eq, PartialEq,
)]
#[serde(rename_all = "snake_case")]
pub enum IncomingSmError {
    #[error("Violated fee policy. Offer amount {offer_amount} Payment amount: {payment_amount}")]
    ViolatedFeePolicy {
        offer_amount: Amount,
        payment_amount: Amount,
    },
    #[error("Invalid offer. Offer hash: {offer_hash} Payment hash: {payment_hash}")]
    InvalidOffer {
        offer_hash: sha256::Hash,
        payment_hash: sha256::Hash,
    },
    #[error("Timed out fetching the offer")]
    TimeoutFetchingOffer { payment_hash: sha256::Hash },
    #[error("Error fetching the contract {payment_hash}. Error: {error_message}")]
    FetchContractError {
        payment_hash: sha256::Hash,
        error_message: String,
    },
    #[error("Invalid preimage. Contract: {contract:?}")]
    InvalidPreimage {
        contract: Box<IncomingContractAccount>,
    },
    #[error("There was a failure when funding the contract: {error_message}")]
    FailedToFundContract { error_message: String },
    #[error("Failed to parse the amount from the invoice: {invoice}")]
    AmountError { invoice: Bolt11Invoice },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct FundingOfferState {
    pub txid: TransactionId,
}

impl FundingOfferState {
    fn transitions(
        &self,
        global_context: &DynGlobalClientContext,
        context: &LightningClientContext,
    ) -> Vec<StateTransition<IncomingStateMachine>> {
        let txid = self.txid;
        vec![StateTransition::new(
            Self::await_funding_success(
                global_context.clone(),
                OutPoint { txid, out_idx: 0 },
                context.clone(),
            ),
            move |_dbtx, result, old_state| {
                Box::pin(Self::transition_funding_success(result, old_state))
            },
        )]
    }

    async fn await_funding_success(
        global_context: DynGlobalClientContext,
        out_point: OutPoint,
        context: LightningClientContext,
    ) -> Result<(), IncomingSmError> {
        debug!("Awaiting funding success for outpoint: {out_point:?}");
        for retry in 0.. {
            let sleep = (retry * 15).min(90);
            match global_context
                .api()
                .await_output_outcome::<LightningOutputOutcome>(
                    out_point,
                    Duration::from_secs(90),
                    &context.ln_decoder,
                )
                .await
            {
                Ok(_) => {
                    debug!("Funding success for outpoint: {out_point:?}");
                    return Ok(());
                }
                Err(e) if e.is_rejected() => {
                    warn!("Funding failed for outpoint: {out_point:?}: {e:?}");
                    return Err(IncomingSmError::FailedToFundContract {
                        error_message: e.to_string(),
                    });
                }
                Err(e) => {
                    e.report_if_important();
                    debug!(error = %e, "Awaiting output outcome failed, retrying in {sleep}s",);
                }
            }
            // give some time for other things to run
            fedimint_core::runtime::sleep(Duration::from_secs(sleep)).await;
        }

        unreachable!("there is too many u64s to ever get here")
    }

    async fn transition_funding_success(
        result: Result<(), IncomingSmError>,
        old_state: IncomingStateMachine,
    ) -> IncomingStateMachine {
        let txid = match old_state.state {
            IncomingSmStates::FundingOffer(refund) => refund.txid,
            _ => panic!("Invalid state transition"),
        };

        match result {
            Ok(_) => IncomingStateMachine {
                common: old_state.common,
                state: IncomingSmStates::DecryptingPreimage(DecryptingPreimageState { txid }),
            },
            Err(error) => IncomingStateMachine {
                common: old_state.common,
                state: IncomingSmStates::FundingFailed { error },
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct DecryptingPreimageState {
    txid: TransactionId,
}

impl DecryptingPreimageState {
    fn transitions(
        &self,
        common: &IncomingSmCommon,
        global_context: &DynGlobalClientContext,
        context: &LightningClientContext,
    ) -> Vec<StateTransition<IncomingStateMachine>> {
        let success_context = global_context.clone();
        let gateway_context = context.clone();

        vec![StateTransition::new(
            Self::await_preimage_decryption(success_context.clone(), common.contract_id),
            move |dbtx, result, old_state| {
                let gateway_context = gateway_context.clone();
                let success_context = success_context.clone();
                Box::pin(Self::transition_incoming_contract_funded(
                    result,
                    old_state,
                    dbtx,
                    success_context,
                    gateway_context,
                ))
            },
        )]
    }

    async fn await_preimage_decryption(
        global_context: DynGlobalClientContext,
        contract_id: ContractId,
    ) -> Result<Preimage, IncomingSmError> {
        loop {
            debug!("Awaiting preimage decryption for contract {contract_id:?}");
            match global_context
                .module_api()
                .wait_preimage_decrypted(contract_id)
                .await
            {
                Ok((incoming_contract_account, preimage)) => match preimage {
                    Some(preimage) => {
                        debug!("Preimage decrypted for contract {contract_id:?}");
                        return Ok(preimage);
                    }
                    None => {
                        info!("Invalid preimage for contract {contract_id:?}");
                        return Err(IncomingSmError::InvalidPreimage {
                            contract: Box::new(incoming_contract_account),
                        });
                    }
                },
                Err(error) => {
                    warn!("Incoming contract {contract_id:?} error waiting for preimage decryption: {error:?}, will keep retrying...");
                }
            }

            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn transition_incoming_contract_funded(
        result: Result<Preimage, IncomingSmError>,
        old_state: IncomingStateMachine,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
        context: LightningClientContext,
    ) -> IncomingStateMachine {
        assert!(matches!(
            old_state.state,
            IncomingSmStates::DecryptingPreimage(_)
        ));

        match result {
            Ok(preimage) => {
                let contract_id = old_state.common.contract_id;
                let payment_hash = old_state.common.payment_hash;
                set_payment_result(
                    &mut dbtx.module_tx(),
                    payment_hash,
                    PayType::Internal(old_state.common.operation_id),
                    contract_id,
                    Amount::from_msats(0),
                )
                .await;

                IncomingStateMachine {
                    common: old_state.common,
                    state: IncomingSmStates::Preimage(preimage),
                }
            }
            Err(IncomingSmError::InvalidPreimage { contract }) => {
                Self::refund_incoming_contract(dbtx, global_context, context, old_state, contract)
                    .await
            }
            Err(e) => IncomingStateMachine {
                common: old_state.common,
                state: IncomingSmStates::Failure(format!(
                    "Unexpected internal error occurred while decrypting the preimage: {e:?}"
                )),
            },
        }
    }

    async fn refund_incoming_contract(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
        context: LightningClientContext,
        old_state: IncomingStateMachine,
        contract: Box<IncomingContractAccount>,
    ) -> IncomingStateMachine {
        debug!("Refunding incoming contract {contract:?}");
        let claim_input = contract.claim();
        let client_input = ClientInput::<LightningInput, IncomingStateMachine> {
            input: claim_input,
            amount: contract.amount,
            state_machines: Arc::new(|_, _| vec![]),
            keys: vec![context.redeem_key],
        };

        let out_points = global_context.claim_input(dbtx, client_input).await.1;
        debug!("Refunded incoming contract {contract:?} with {out_points:?}");

        IncomingStateMachine {
            common: old_state.common,
            state: IncomingSmStates::RefundSubmitted {
                out_points,
                error: IncomingSmError::InvalidPreimage { contract },
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct AwaitingPreimageDecryption {
    txid: TransactionId,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct PreimageState {
    preimage: Preimage,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct RefundSuccessState {
    refund_txid: TransactionId,
}
