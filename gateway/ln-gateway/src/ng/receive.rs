use std::sync::Arc;
use std::time::Duration;

use bitcoin_hashes::{sha256, Hash};
use fedimint_client::sm::{ClientSMDatabaseTransaction, OperationId, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_ln_client::api::LnFederationApi;
use fedimint_ln_common::contracts::incoming::IncomingContractAccount;
use fedimint_ln_common::contracts::{DecryptedPreimage, Preimage};
use fedimint_ln_common::{LightningInput, LightningOutputOutcome};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use super::{GatewayClientContext, GatewayClientStateMachines};
use crate::gatewaylnrpc::SubscribeInterceptHtlcsResponse;

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum ReceiveError {
    #[error("Violated fee policy")]
    ViolatedFeePolicy,
    #[error("Invalid offer")]
    InvalidOffer,
    #[error("Timeout")]
    Timeout,
    #[error("Fetch contract error")]
    FetchContractError,
    #[error("Incoming contract error")]
    IncomingContractError,
    #[error("Invalid preimage")]
    InvalidPreimage(Box<IncomingContractAccount>),
    #[error("Output outcome error")]
    OutputOutcomeError,
    #[error("Route htlc error")]
    RouteHtlcError,
    #[error("Incoming contract not found")]
    IncomingContractNotFound,
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that executes the Lightning payment on behalf of
/// the fedimint user that requested an invoice to be paid.
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
pub enum GatewayReceiveStates {
    FundingOffer(FundingOfferState),
    DecryptingPreimage(DecryptingPreimageState),
    Preimage(Preimage),
    RefundSubmitted(TransactionId),
    FundingFailed(String),
    Failure(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayReceiveCommon {
    pub operation_id: OperationId,
    pub htlc: Htlc,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayReceiveStateMachine {
    pub common: GatewayReceiveCommon,
    pub state: GatewayReceiveStates,
}

impl State for GatewayReceiveStateMachine {
    type ModuleContext = GatewayClientContext;

    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        match &self.state {
            GatewayReceiveStates::FundingOffer(state) => state.transitions(global_context, context),
            GatewayReceiveStates::DecryptingPreimage(state) => {
                state.transitions(global_context, context, &self.common)
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

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct Htlc {
    /// The HTLC payment hash.
    pub payment_hash: sha256::Hash,
    /// The incoming HTLC amount in millisatoshi.
    pub incoming_amount_msat: Amount,
    /// The outgoing HTLC amount in millisatoshi
    pub outgoing_amount_msat: Amount,
    /// The incoming HTLC expiry
    pub incoming_expiry: u32,
    /// The short channel id of the HTLC.
    pub short_channel_id: u64,
    /// The id of the incoming channel
    pub incoming_chan_id: u64,
    /// The index of the incoming htlc in the incoming channel
    pub htlc_id: u64,
}

impl TryFrom<SubscribeInterceptHtlcsResponse> for Htlc {
    type Error = anyhow::Error;

    fn try_from(s: SubscribeInterceptHtlcsResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            payment_hash: sha256::Hash::from_slice(&s.payment_hash)?,
            incoming_amount_msat: Amount::from_msats(s.incoming_amount_msat),
            outgoing_amount_msat: Amount::from_msats(s.outgoing_amount_msat),
            incoming_expiry: s.incoming_expiry,
            short_channel_id: s.short_channel_id,
            incoming_chan_id: s.incoming_chan_id,
            htlc_id: s.htlc_id,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct FundingOfferState {
    pub txid: TransactionId,
}

impl FundingOfferState {
    fn transitions(
        &self,
        global_context: &DynGlobalClientContext,
        context: &GatewayClientContext,
    ) -> Vec<StateTransition<GatewayReceiveStateMachine>> {
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
        context: GatewayClientContext,
    ) -> Result<(), ReceiveError> {
        global_context
            .api()
            .await_output_outcome::<LightningOutputOutcome>(
                out_point,
                Duration::from_millis(i32::MAX as u64),
                &context.ln_decoder,
            )
            .await
            .map_err(|_| ReceiveError::OutputOutcomeError)?;
        Ok(())
    }

    async fn transition_funding_success(
        result: Result<(), ReceiveError>,
        old_state: GatewayReceiveStateMachine,
    ) -> GatewayReceiveStateMachine {
        let txid = match old_state.state {
            GatewayReceiveStates::FundingOffer(refund) => refund.txid,
            _ => panic!("Invalid state transition"),
        };

        match result {
            Ok(_) => GatewayReceiveStateMachine {
                common: old_state.common,
                state: GatewayReceiveStates::DecryptingPreimage(DecryptingPreimageState { txid }),
            },
            Err(e) => GatewayReceiveStateMachine {
                common: old_state.common,
                state: GatewayReceiveStates::FundingFailed(e.to_string()),
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
        global_context: &DynGlobalClientContext,
        context: &GatewayClientContext,
        common: &GatewayReceiveCommon,
    ) -> Vec<StateTransition<GatewayReceiveStateMachine>> {
        let success_context = global_context.clone();
        let gateway_context = context.clone();
        vec![StateTransition::new(
            Self::await_preimage_decryption(success_context.clone(), common.clone()),
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
        common: GatewayReceiveCommon,
    ) -> Result<Preimage, ReceiveError> {
        // TODO: Get rid of polling
        let preimage = loop {
            let contract_id = common.htlc.payment_hash.into();
            let contract = global_context
                .module_api()
                .get_incoming_contract(contract_id)
                .await;

            match contract {
                Ok(contract) => match contract.contract.decrypted_preimage {
                    DecryptedPreimage::Pending => {}
                    DecryptedPreimage::Some(preimage) => break preimage,
                    DecryptedPreimage::Invalid => {
                        return Err(ReceiveError::InvalidPreimage(Box::new(contract)));
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
        result: Result<Preimage, ReceiveError>,
        old_state: GatewayReceiveStateMachine,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
    ) -> GatewayReceiveStateMachine {
        assert!(matches!(
            old_state.state,
            GatewayReceiveStates::DecryptingPreimage(_)
        ));

        match result {
            Ok(preimage) => GatewayReceiveStateMachine {
                common: old_state.common,
                state: GatewayReceiveStates::Preimage(preimage),
            },
            Err(ReceiveError::InvalidPreimage(contract)) => {
                Self::refund_incoming_contract(dbtx, global_context, context, old_state, contract)
                    .await
            }
            Err(e) => GatewayReceiveStateMachine {
                common: old_state.common,
                state: GatewayReceiveStates::Failure(format!(
                    "Unexpected internal error occured while decrypting the preimage: {e:?}"
                )),
            },
        }
    }

    async fn refund_incoming_contract(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        old_state: GatewayReceiveStateMachine,
        contract: Box<IncomingContractAccount>,
    ) -> GatewayReceiveStateMachine {
        let claim_input = contract.claim();
        let client_input = ClientInput::<LightningInput, GatewayClientStateMachines> {
            input: claim_input,
            state_machines: Arc::new(|_, _| vec![]),
            keys: vec![context.redeem_key],
        };

        let (refund_txid, _) = global_context.claim_input(dbtx, client_input).await;

        GatewayReceiveStateMachine {
            common: old_state.common,
            state: GatewayReceiveStates::RefundSubmitted(refund_txid),
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
