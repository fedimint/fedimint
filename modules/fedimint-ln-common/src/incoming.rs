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

use bitcoin_hashes::sha256;
use fedimint_client::sm::{ClientSMDatabaseTransaction, OperationId, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::{Amount, OutPoint, TransactionId};
use lightning_invoice::Invoice;
use secp256k1::KeyPair;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use crate::api::LnFederationApi;
use crate::contracts::incoming::IncomingContractAccount;
use crate::contracts::{ContractId, DecryptedPreimage, Preimage};
use crate::{LightningClientContext, LightningInput, LightningOutputOutcome};

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
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum IncomingSmStates {
    FundingOffer(FundingOfferState),
    DecryptingPreimage(DecryptingPreimageState),
    Preimage(Preimage),
    RefundSubmitted {
        txid: TransactionId,
        error: IncomingSmError,
    },
    FundingFailed {
        error: IncomingSmError,
    },
    Failure(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct IncomingSmCommon {
    pub operation_id: OperationId,
    pub contract_id: ContractId,
    pub redeem_key: KeyPair,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct IncomingStateMachine {
    pub common: IncomingSmCommon,
    pub state: IncomingSmStates,
}

impl State for IncomingStateMachine {
    type ModuleContext = LightningClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        match &self.state {
            IncomingSmStates::FundingOffer(state) => state.transitions(global_context, context),
            IncomingSmStates::DecryptingPreimage(state) => {
                state.transitions(&self.common, global_context)
            }
            _ => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        self.common.operation_id
    }
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
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
    AmountError { invoice: Invoice },
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
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
        global_context
            .api()
            .await_output_outcome::<LightningOutputOutcome>(
                out_point,
                Duration::from_millis(i32::MAX as u64),
                &context.ln_decoder,
            )
            .await
            .map_err(|e| IncomingSmError::FailedToFundContract {
                error_message: e.to_string(),
            })?;
        Ok(())
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

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct DecryptingPreimageState {
    txid: TransactionId,
}

impl DecryptingPreimageState {
    fn transitions(
        &self,
        common: &IncomingSmCommon,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<IncomingStateMachine>> {
        let success_context = global_context.clone();

        vec![StateTransition::new(
            Self::await_preimage_decryption(success_context.clone(), common.contract_id),
            move |dbtx, result, old_state| {
                let success_context = success_context.clone();
                Box::pin(Self::transition_incoming_contract_funded(
                    result,
                    old_state,
                    dbtx,
                    success_context,
                ))
            },
        )]
    }

    async fn await_preimage_decryption(
        global_context: DynGlobalClientContext,
        contract_id: ContractId,
    ) -> Result<Preimage, IncomingSmError> {
        // TODO: Get rid of polling
        let preimage = loop {
            let contract = global_context
                .module_api()
                .get_incoming_contract(contract_id)
                .await;

            match contract {
                Ok(contract) => match contract.contract.decrypted_preimage {
                    DecryptedPreimage::Pending => {}
                    DecryptedPreimage::Some(preimage) => break preimage,
                    DecryptedPreimage::Invalid => {
                        return Err(IncomingSmError::InvalidPreimage {
                            contract: Box::new(contract),
                        });
                    }
                },
                Err(e) => {
                    error!("Failed to fetch contract {e:?}");
                }
            }

            sleep(Duration::from_secs(1)).await;
        };

        Ok(preimage)
    }

    async fn transition_incoming_contract_funded(
        result: Result<Preimage, IncomingSmError>,
        old_state: IncomingStateMachine,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
    ) -> IncomingStateMachine {
        assert!(matches!(
            old_state.state,
            IncomingSmStates::DecryptingPreimage(_)
        ));

        match result {
            Ok(preimage) => IncomingStateMachine {
                common: old_state.common,
                state: IncomingSmStates::Preimage(preimage),
            },
            Err(IncomingSmError::InvalidPreimage { contract }) => {
                Self::refund_incoming_contract(dbtx, global_context, old_state, contract).await
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
        old_state: IncomingStateMachine,
        contract: Box<IncomingContractAccount>,
    ) -> IncomingStateMachine {
        let claim_input = contract.claim();
        let client_input = ClientInput::<LightningInput, IncomingStateMachine> {
            input: claim_input,
            state_machines: Arc::new(|_, _| vec![]),
            keys: vec![old_state.common.redeem_key],
        };

        let (refund_txid, _) = global_context.claim_input(dbtx, client_input).await;

        IncomingStateMachine {
            common: old_state.common,
            state: IncomingSmStates::RefundSubmitted {
                txid: refund_txid,
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
