use std::sync::Arc;
use std::time::Duration;

use bitcoin_hashes::sha256;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::{GlobalFederationApi, OutputOutcomeError};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::contracts::outgoing::OutgoingContractData;
use fedimint_ln_common::contracts::{ContractId, IdentifiableContract};
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_ln_common::{
    LightningClientContext, LightningGateway, LightningInput, LightningOutputOutcome, PrunedInvoice,
};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, warn};

use crate::{set_payment_result, LightningClientStateMachines, PayType};

const GATEWAY_API_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_secs(1);

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that requests the lightning gateway to pay an invoice on
/// behalf of a federation client.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///  CreatedOutgoingLnContract -- await transaction failed --> Canceled
///  CreatedOutgoingLnContract -- await transaction acceptance --> Funded    
///  Funded -- await gateway payment success  --> Success
///  Funded -- await gateway payment failed --> Refundable
///  Refundable -- gateway issued refunded --> Refund
///  Refundable -- transaction timeout --> Refund
///  Refund -- await transaction acceptance --> Refunded
///  Refund -- await transaction rejected --> Failure
/// ```
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum LightningPayStates {
    CreatedOutgoingLnContract(LightningPayCreatedOutgoingLnContract),
    Canceled,
    Funded(LightningPayFunded),
    Success(String),
    Refundable(LightningPayRefundable),
    Refund(LightningPayRefund),
    Refunded(Vec<OutPoint>),
    Failure(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningPayCommon {
    pub operation_id: OperationId,
    pub federation_id: FederationId,
    pub contract: OutgoingContractData,
    pub gateway_fee: Amount,
    pub preimage_auth: sha256::Hash,
    pub invoice: lightning_invoice::Bolt11Invoice,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningPayStateMachine {
    pub common: LightningPayCommon,
    pub state: LightningPayStates,
}

impl State for LightningPayStateMachine {
    type ModuleContext = LightningClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            LightningPayStates::CreatedOutgoingLnContract(created_outgoing_ln_contract) => {
                created_outgoing_ln_contract.transitions(context, global_context)
            }
            LightningPayStates::Canceled => {
                vec![]
            }
            LightningPayStates::Funded(funded) => funded.transitions(self.common.clone()),
            LightningPayStates::Success(_) => {
                vec![]
            }
            LightningPayStates::Refundable(refundable) => {
                refundable.transitions(self.common.clone(), global_context.clone())
            }
            LightningPayStates::Refund(refund) => refund.transitions(&self.common, global_context),
            LightningPayStates::Refunded(_) => {
                vec![]
            }
            LightningPayStates::Failure(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningPayCreatedOutgoingLnContract {
    pub funding_txid: TransactionId,
    pub contract_id: ContractId,
    pub gateway: LightningGateway,
}

impl LightningPayCreatedOutgoingLnContract {
    fn transitions(
        &self,
        context: &LightningClientContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningPayStateMachine>> {
        let txid = self.funding_txid;
        let contract_id = self.contract_id;
        let success_context = global_context.clone();
        let gateway = self.gateway.clone();
        vec![StateTransition::new(
            Self::await_outgoing_contract_funded(
                context.ln_decoder.clone(),
                success_context,
                txid,
                contract_id,
            ),
            move |_dbtx, result, old_state| {
                Box::pin(Self::transition_outgoing_contract_funded(
                    result,
                    old_state,
                    gateway.clone(),
                ))
            },
        )]
    }

    async fn await_outgoing_contract_funded(
        module_decoder: Decoder,
        global_context: DynGlobalClientContext,
        txid: TransactionId,
        contract_id: ContractId,
    ) -> Result<u32, GatewayPayError> {
        let out_point = OutPoint { txid, out_idx: 0 };

        loop {
            match global_context
                .api()
                .await_output_outcome::<LightningOutputOutcome>(
                    out_point,
                    Duration::from_millis(i32::MAX as u64),
                    &module_decoder,
                )
                .await
            {
                Ok(_) => break,
                Err(OutputOutcomeError::Federation(e)) if e.is_retryable() => {
                    debug!(
                        "Awaiting output outcome failed, retrying in {}s",
                        RETRY_DELAY.as_secs_f64()
                    );
                    sleep(RETRY_DELAY).await;
                }
                Err(_) => {
                    return Err(GatewayPayError::OutgoingContractError);
                }
            }
        }

        let contract = loop {
            match global_context
                .module_api()
                .fetch_outgoing_contract(contract_id)
                .await
            {
                Ok(contract) => {
                    break contract;
                }
                Err(e) if e.is_retryable() => {
                    debug!(
                        "Fetching contract failed, retrying in {}s",
                        RETRY_DELAY.as_secs_f64()
                    );
                    sleep(RETRY_DELAY).await;
                }
                Err(_) => {
                    return Err(GatewayPayError::OutgoingContractError);
                }
            }
        };
        Ok(contract.contract.timelock)
    }

    async fn transition_outgoing_contract_funded(
        result: Result<u32, GatewayPayError>,
        old_state: LightningPayStateMachine,
        gateway: LightningGateway,
    ) -> LightningPayStateMachine {
        assert!(matches!(
            old_state.state,
            LightningPayStates::CreatedOutgoingLnContract(_)
        ));

        match result {
            Ok(timelock) => {
                // Success case: funding transaction is accepted
                let common = old_state.common.clone();
                let payload = if gateway.supports_private_payments {
                    PayInvoicePayload::new_pruned(common.clone())
                } else {
                    PayInvoicePayload::new(common.clone())
                };
                LightningPayStateMachine {
                    common: old_state.common,
                    state: LightningPayStates::Funded(LightningPayFunded {
                        payload,
                        gateway,
                        timelock,
                    }),
                }
            }
            Err(_) => {
                // Failure case: funding transaction is rejected
                LightningPayStateMachine {
                    common: old_state.common,
                    state: LightningPayStates::Canceled,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningPayFunded {
    payload: PayInvoicePayload,
    gateway: LightningGateway,
    timelock: u32,
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayPayError {
    #[error("Lightning Gateway failed to pay invoice. ErrorCode: {error_code:?} ErrorMessage: {error_message}")]
    GatewayInternalError {
        error_code: Option<u16>,
        error_message: String,
    },
    #[error("OutgoingContract was not created in the federation")]
    OutgoingContractError,
}

impl LightningPayFunded {
    fn transitions(
        &self,
        common: LightningPayCommon,
    ) -> Vec<StateTransition<LightningPayStateMachine>> {
        let gateway = self.gateway.clone();
        let payload = self.payload.clone();
        let contract_id = self.payload.contract_id;
        let timelock = self.timelock;
        let payment_hash = *common.invoice.payment_hash();
        vec![StateTransition::new(
            Self::gateway_pay_invoice(gateway, payload),
            move |dbtx, result, old_state| {
                Box::pin(Self::transition_outgoing_contract_execution(
                    result,
                    old_state,
                    contract_id,
                    timelock,
                    dbtx,
                    payment_hash,
                    common.clone(),
                ))
            },
        )]
    }

    async fn gateway_pay_invoice(
        gateway: LightningGateway,
        payload: PayInvoicePayload,
    ) -> Result<String, GatewayPayError> {
        // Abort the payment if we can't reach the gateway within 30 seconds
        // to prevent unexpected delays for the user.
        let deadline = fedimint_core::time::now() + GATEWAY_API_TIMEOUT;

        let mut last_error = None;
        while fedimint_core::time::now() < deadline {
            match Self::try_gateway_pay_invoice(gateway.clone(), payload.clone()).await {
                Ok(preimage) => return Ok(preimage),
                Err(e) => {
                    warn!("Error while trying to reach gateway: {e}");
                    last_error = Some(e);
                    sleep(RETRY_DELAY).await;
                }
            }
        }

        Err(last_error.expect("Error was set"))
    }

    async fn try_gateway_pay_invoice(
        gateway: LightningGateway,
        payload: PayInvoicePayload,
    ) -> Result<String, GatewayPayError> {
        let response = reqwest::Client::new()
            .post(
                gateway
                    .api
                    .join("pay_invoice")
                    .expect("'pay_invoice' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(&payload)
            .send()
            .await
            .map_err(|e| GatewayPayError::GatewayInternalError {
                error_code: None,
                error_message: e.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(GatewayPayError::GatewayInternalError {
                error_code: Some(response.status().as_u16()),
                error_message: response
                    .text()
                    .await
                    .expect("Could not retrieve text from response"),
            });
        }

        let preimage =
            response
                .text()
                .await
                .map_err(|_| GatewayPayError::GatewayInternalError {
                    error_code: None,
                    error_message: "Error retrieving preimage from response".to_string(),
                })?;
        let length = preimage.len();
        Ok(preimage[1..length - 1].to_string())
    }

    async fn transition_outgoing_contract_execution(
        result: Result<String, GatewayPayError>,
        old_state: LightningPayStateMachine,
        contract_id: ContractId,
        timelock: u32,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        payment_hash: sha256::Hash,
        common: LightningPayCommon,
    ) -> LightningPayStateMachine {
        match result {
            Ok(preimage) => {
                set_payment_result(
                    &mut dbtx.module_tx(),
                    payment_hash,
                    PayType::Lightning(old_state.common.operation_id),
                    contract_id,
                    common.gateway_fee,
                )
                .await;
                LightningPayStateMachine {
                    common: old_state.common,
                    state: LightningPayStates::Success(preimage),
                }
            }
            Err(e) => LightningPayStateMachine {
                common: old_state.common,
                state: LightningPayStates::Refundable(LightningPayRefundable {
                    contract_id,
                    block_timelock: timelock,
                    error: e,
                }),
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningPayRefundable {
    contract_id: ContractId,
    pub block_timelock: u32,
    pub error: GatewayPayError,
}

impl LightningPayRefundable {
    fn transitions(
        &self,
        common: LightningPayCommon,
        global_context: DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningPayStateMachine>> {
        let contract_id = self.contract_id;
        let timeout_global_context = global_context.clone();
        let timeout_common = common.clone();
        let timelock = self.block_timelock;
        vec![
            StateTransition::new(
                Self::await_contract_cancellable(contract_id, global_context.clone()),
                move |dbtx, (), old_state| {
                    Box::pin(Self::try_refund_outgoing_contract(
                        old_state,
                        common.clone(),
                        dbtx,
                        global_context.clone(),
                    ))
                },
            ),
            StateTransition::new(
                Self::await_contract_timeout(timeout_global_context.clone(), timelock),
                move |dbtx, (), old_state| {
                    Box::pin(Self::try_refund_outgoing_contract(
                        old_state,
                        timeout_common.clone(),
                        dbtx,
                        timeout_global_context.clone(),
                    ))
                },
            ),
        ]
    }

    /// Claims a refund for an expired or cancelled outgoing contract
    ///
    /// This can be necessary when the Lightning gateway cannot route the
    /// payment, is malicious or offline. The function returns the out point
    /// of the e-cash output generated as change.
    async fn try_refund_outgoing_contract(
        old_state: LightningPayStateMachine,
        common: LightningPayCommon,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
    ) -> LightningPayStateMachine {
        let contract_data = common.contract;
        let (refund_key, refund_input) = (
            contract_data.recovery_key,
            contract_data.contract_account.refund(),
        );

        let refund_client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
            input: refund_input,
            keys: vec![refund_key],
            // The input of the refund tx is managed by this state machine, so no new state machines
            // need to be created
            state_machines: Arc::new(|_, _| vec![]),
        };

        let (txid, out_points) = global_context.claim_input(dbtx, refund_client_input).await;

        LightningPayStateMachine {
            common: old_state.common,
            state: LightningPayStates::Refund(LightningPayRefund { txid, out_points }),
        }
    }

    async fn await_contract_cancellable(
        contract_id: ContractId,
        global_context: DynGlobalClientContext,
    ) {
        loop {
            // If we fail to get the contract from the federation, we need to keep retrying
            // until we successfully do.
            match global_context
                .module_api()
                .wait_outgoing_contract_cancelled(contract_id)
                .await
            {
                Ok(_) => return,
                Err(error) => {
                    error!("Error waiting for outgoing contract to be cancelled: {error:?}");
                }
            }

            sleep(RETRY_DELAY).await;
        }
    }

    async fn await_contract_timeout(global_context: DynGlobalClientContext, timelock: u32) {
        loop {
            match global_context
                .module_api()
                .wait_block_height(timelock as u64)
                .await
            {
                Ok(_) => return,
                Err(error) => error!("Error waiting for block height: {timelock} {error:?}"),
            }

            sleep(RETRY_DELAY).await;
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningPayRefund {
    txid: TransactionId,
    out_points: Vec<OutPoint>,
}

impl LightningPayRefund {
    fn transitions(
        &self,
        common: &LightningPayCommon,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningPayStateMachine>> {
        let refund_out_points = self.out_points.clone();
        vec![StateTransition::new(
            Self::await_refund_success(common.clone(), global_context.clone(), self.txid),
            move |_dbtx, result, old_state| {
                let refund_out_points = refund_out_points.clone();
                Box::pin(Self::transition_refund_success(
                    result,
                    old_state,
                    refund_out_points,
                ))
            },
        )]
    }

    async fn await_refund_success(
        common: LightningPayCommon,
        global_context: DynGlobalClientContext,
        refund_txid: TransactionId,
    ) -> Result<(), String> {
        // No network calls are done here, we just await other state machines, so no
        // retry logic is needed
        global_context
            .await_tx_accepted(common.operation_id, refund_txid)
            .await
    }

    async fn transition_refund_success(
        result: Result<(), String>,
        old_state: LightningPayStateMachine,
        refund_out_points: Vec<OutPoint>,
    ) -> LightningPayStateMachine {
        match result {
            Ok(_) => {
                // Refund successful
                LightningPayStateMachine {
                    common: old_state.common,
                    state: LightningPayStates::Refunded(refund_out_points),
                }
            }
            Err(_) => {
                // Refund failure
                LightningPayStateMachine {
                    common: old_state.common,
                    state: LightningPayStates::Failure(
                        "Refund Transaction was rejected.".to_string(),
                    ),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decodable, Encodable)]
pub struct PayInvoicePayload {
    pub federation_id: FederationId,
    pub contract_id: ContractId,
    /// Metadata on how to obtain the preimage
    pub payment_data: PaymentData,
    pub preimage_auth: sha256::Hash,
}

impl PayInvoicePayload {
    fn new(common: LightningPayCommon) -> Self {
        Self {
            contract_id: common.contract.contract_account.contract.contract_id(),
            federation_id: common.federation_id,
            preimage_auth: common.preimage_auth,
            payment_data: PaymentData::Invoice(common.invoice),
        }
    }

    fn new_pruned(common: LightningPayCommon) -> Self {
        Self {
            contract_id: common.contract.contract_account.contract.contract_id(),
            federation_id: common.federation_id,
            preimage_auth: common.preimage_auth,
            payment_data: PaymentData::PrunedInvoice(
                common.invoice.try_into().expect("Invoice has amount"),
            ),
        }
    }
}

/// Data needed to pay an invoice, may be the whole invoice or only the required
/// parts of it.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decodable, Encodable)]
#[serde(rename_all = "snake_case")]
pub enum PaymentData {
    Invoice(Bolt11Invoice),
    PrunedInvoice(PrunedInvoice),
}

impl PaymentData {
    pub fn amount(&self) -> Option<Amount> {
        match self {
            PaymentData::Invoice(invoice) => {
                invoice.amount_milli_satoshis().map(Amount::from_msats)
            }
            PaymentData::PrunedInvoice(PrunedInvoice { amount, .. }) => Some(*amount),
        }
    }

    pub fn destination(&self) -> secp256k1_zkp::PublicKey {
        match self {
            PaymentData::Invoice(invoice) => invoice
                .payee_pub_key()
                .cloned()
                .unwrap_or_else(|| invoice.recover_payee_pub_key()),
            PaymentData::PrunedInvoice(PrunedInvoice { destination, .. }) => *destination,
        }
    }

    pub fn payment_hash(&self) -> sha256::Hash {
        match self {
            PaymentData::Invoice(invoice) => *invoice.payment_hash(),
            PaymentData::PrunedInvoice(PrunedInvoice { payment_hash, .. }) => *payment_hash,
        }
    }

    pub fn route_hints(&self) -> Vec<RouteHint> {
        match self {
            PaymentData::Invoice(invoice) => {
                invoice.route_hints().into_iter().map(Into::into).collect()
            }
            PaymentData::PrunedInvoice(PrunedInvoice { route_hints, .. }) => route_hints.clone(),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expiry_timestamp() < duration_since_epoch().as_secs()
    }

    /// Returns the expiry timestamp in seconds since the UNIX epoch
    pub fn expiry_timestamp(&self) -> u64 {
        match self {
            PaymentData::Invoice(invoice) => invoice
                .expires_at()
                .map(|t| t.as_secs())
                .unwrap_or(u64::MAX),
            PaymentData::PrunedInvoice(PrunedInvoice {
                expiry_timestamp, ..
            }) => *expiry_timestamp,
        }
    }
}
