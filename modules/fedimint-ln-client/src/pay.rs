use std::time::{Duration, SystemTime};

use bitcoin30::hashes::sha256;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientInputBundle};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::bitcoin_migration::bitcoin30_to_bitcoin32_secp256k1_pubkey;
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::{secp256k1, Amount, OutPoint, TransactionId};
use fedimint_ln_common::contracts::outgoing::OutgoingContractData;
use fedimint_ln_common::contracts::{ContractId, IdentifiableContract};
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_ln_common::{LightningGateway, LightningInput, LightningOutputOutcome, PrunedInvoice};
use lightning_invoice::Bolt11Invoice;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, warn};

pub use self::lightningpay::LightningPayStates;
use crate::api::LnFederationApi;
use crate::{set_payment_result, LightningClientContext, PayType};

const RETRY_DELAY: Duration = Duration::from_secs(1);

/// `lightningpay` module is needed to suppress the deprecation warning on the
/// enum declaration. Suppressing the deprecation warning on the enum
/// declaration is not enough, since the `derive` statement causes it to be
/// ignored for some reason, so instead the enum declaration is wrapped
/// in its own module.
#[allow(deprecated)]
pub(super) mod lightningpay {
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::OutPoint;

    use super::{
        LightningPayCreatedOutgoingLnContract, LightningPayFunded, LightningPayRefund,
        LightningPayRefundable,
    };

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
    ///  Funded -- await gateway cancel payment --> Refund
    ///  Funded -- await payment timeout --> Refund
    ///  Funded -- unrecoverable payment error --> Failure
    ///  Refundable -- gateway issued refunded --> Refund
    ///  Refundable -- transaction timeout --> Refund
    /// ```
    #[allow(clippy::large_enum_variant)]
    #[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
    pub enum LightningPayStates {
        CreatedOutgoingLnContract(LightningPayCreatedOutgoingLnContract),
        FundingRejected,
        Funded(LightningPayFunded),
        Success(String),
        #[deprecated(
            since = "0.4.0",
            note = "Pay State Machine skips over this state and will retry payments until cancellation or timeout"
        )]
        Refundable(LightningPayRefundable),
        Refund(LightningPayRefund),
        #[deprecated(
            since = "0.4.0",
            note = "Pay State Machine does not need to wait for the refund tx to be accepted"
        )]
        Refunded(Vec<OutPoint>),
        Failure(String),
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct LightningPayCommon {
    pub operation_id: OperationId,
    pub federation_id: FederationId,
    pub contract: OutgoingContractData,
    pub gateway_fee: Amount,
    pub preimage_auth: sha256::Hash,
    pub invoice: lightning_invoice::Bolt11Invoice,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct LightningPayStateMachine {
    pub common: LightningPayCommon,
    pub state: LightningPayStates,
}

impl State for LightningPayStateMachine {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            LightningPayStates::CreatedOutgoingLnContract(created_outgoing_ln_contract) => {
                created_outgoing_ln_contract.transitions(context, global_context)
            }
            LightningPayStates::Funded(funded) => {
                funded.transitions(self.common.clone(), context.clone(), global_context.clone())
            }
            #[allow(deprecated)]
            LightningPayStates::Refundable(refundable) => {
                refundable.transitions(self.common.clone(), global_context.clone())
            }
            #[allow(deprecated)]
            LightningPayStates::Success(_)
            | LightningPayStates::FundingRejected
            | LightningPayStates::Refund(_)
            | LightningPayStates::Refunded(_)
            | LightningPayStates::Failure(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
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
                let gateway = gateway.clone();
                Box::pin(async move {
                    Self::transition_outgoing_contract_funded(&result, old_state, gateway)
                })
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
                Err(e) if e.is_rejected() => {
                    return Err(GatewayPayError::OutgoingContractError);
                }
                Err(e) => {
                    e.report_if_important();

                    debug!(
                        error = e.to_string(),
                        transaction_id = txid.to_string(),
                        contract_id = contract_id.to_string(),
                        "Retrying in {}s",
                        RETRY_DELAY.as_secs_f64()
                    );
                    sleep(RETRY_DELAY).await;
                }
            }
        }

        let contract = loop {
            match global_context
                .module_api()
                .get_outgoing_contract(contract_id)
                .await
            {
                Ok(contract) => {
                    break contract;
                }
                Err(e) => {
                    e.report_if_important();
                    debug!(
                        "Fetching contract failed, retrying in {}s",
                        RETRY_DELAY.as_secs_f64()
                    );
                    sleep(RETRY_DELAY).await;
                }
            }
        };
        Ok(contract.contract.timelock)
    }

    fn transition_outgoing_contract_funded(
        result: &Result<u32, GatewayPayError>,
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
                        timelock: *timelock,
                        funding_time: fedimint_core::time::now(),
                    }),
                }
            }
            Err(_) => {
                // Failure case: funding transaction is rejected
                LightningPayStateMachine {
                    common: old_state.common,
                    state: LightningPayStates::FundingRejected,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct LightningPayFunded {
    pub payload: PayInvoicePayload,
    pub gateway: LightningGateway,
    pub timelock: u32,
    pub funding_time: SystemTime,
}

#[derive(
    Error, Debug, Hash, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq,
)]
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
        context: LightningClientContext,
        global_context: DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningPayStateMachine>> {
        let gateway = self.gateway.clone();
        let payload = self.payload.clone();
        let contract_id = self.payload.contract_id;
        let timelock = self.timelock;
        let payment_hash = *common.invoice.payment_hash();
        let success_common = common.clone();
        let timeout_common = common.clone();
        let timeout_global_context = global_context.clone();
        vec![
            StateTransition::new(
                Self::gateway_pay_invoice(gateway, payload, context, self.funding_time),
                move |dbtx, result, old_state| {
                    Box::pin(Self::transition_outgoing_contract_execution(
                        result,
                        old_state,
                        contract_id,
                        dbtx,
                        payment_hash,
                        success_common.clone(),
                    ))
                },
            ),
            StateTransition::new(
                await_contract_cancelled(contract_id, global_context.clone()),
                move |dbtx, (), old_state| {
                    Box::pin(try_refund_outgoing_contract(
                        old_state,
                        common.clone(),
                        dbtx,
                        global_context.clone(),
                        format!("Gateway cancelled contract: {contract_id}"),
                    ))
                },
            ),
            StateTransition::new(
                await_contract_timeout(timeout_global_context.clone(), timelock),
                move |dbtx, (), old_state| {
                    Box::pin(try_refund_outgoing_contract(
                        old_state,
                        timeout_common.clone(),
                        dbtx,
                        timeout_global_context.clone(),
                        format!("Outgoing contract timed out, BlockHeight: {timelock}"),
                    ))
                },
            ),
        ]
    }

    async fn gateway_pay_invoice(
        gateway: LightningGateway,
        payload: PayInvoicePayload,
        context: LightningClientContext,
        start: SystemTime,
    ) -> Result<String, GatewayPayError> {
        const GATEWAY_INTERNAL_ERROR_RETRY_INTERVAL: Duration = Duration::from_secs(10);
        const TIMEOUT_DURATION: Duration = Duration::from_secs(180);

        loop {
            // We do not want to retry until the block timeout, since it will be unintuitive
            // for users for their payment to succeed after awhile. We will try
            // to pay the invoice until `TIMEOUT_DURATION` is hit, at which
            // point this future will block and the user will be able
            // to claim their funds once the block timeout is hit, or the gateway cancels
            // the outgoing payment.
            let elapsed = fedimint_core::time::now()
                .duration_since(start)
                .unwrap_or_default();
            if elapsed > TIMEOUT_DURATION {
                std::future::pending::<()>().await;
            }

            match context
                .gateway_conn
                .pay_invoice(gateway.clone(), payload.clone())
                .await
            {
                Ok(preimage) => return Ok(preimage),
                Err(error) => {
                    match error.clone() {
                        GatewayPayError::GatewayInternalError {
                            error_code,
                            error_message,
                        } => {
                            // Retry faster if we could not contact the gateway
                            if let Some(error_code) = error_code {
                                if error_code == StatusCode::NOT_FOUND.as_u16() {
                                    warn!(
                                        ?error_message,
                                        ?payload,
                                        ?gateway,
                                        ?RETRY_DELAY,
                                        "Could not contact gateway"
                                    );
                                    sleep(RETRY_DELAY).await;
                                    continue;
                                }
                            }
                        }
                        GatewayPayError::OutgoingContractError => {
                            return Err(error);
                        }
                    }

                    warn!(
                        ?error,
                        ?payload,
                        ?gateway,
                        ?GATEWAY_INTERNAL_ERROR_RETRY_INTERVAL,
                        "Gateway Internal Error. Could not complete payment. Trying again..."
                    );
                    sleep(GATEWAY_INTERNAL_ERROR_RETRY_INTERVAL).await;
                }
            }
        }
    }

    async fn transition_outgoing_contract_execution(
        result: Result<String, GatewayPayError>,
        old_state: LightningPayStateMachine,
        contract_id: ContractId,
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
                state: LightningPayStates::Failure(e.to_string()),
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
// Deprecated: SM skips over this state now and will retry payments until
// cancellation or timeout
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
                await_contract_cancelled(contract_id, global_context.clone()),
                move |dbtx, (), old_state| {
                    Box::pin(try_refund_outgoing_contract(
                        old_state,
                        common.clone(),
                        dbtx,
                        global_context.clone(),
                        format!("Refundable: Gateway cancelled contract: {contract_id}"),
                    ))
                },
            ),
            StateTransition::new(
                await_contract_timeout(timeout_global_context.clone(), timelock),
                move |dbtx, (), old_state| {
                    Box::pin(try_refund_outgoing_contract(
                        old_state,
                        timeout_common.clone(),
                        dbtx,
                        timeout_global_context.clone(),
                        format!("Refundable: Outgoing contract timed out. ContractId: {contract_id} BlockHeight: {timelock}"),
                    ))
                },
            ),
        ]
    }
}

/// Waits for a contract with `contract_id` to be cancelled by the gateway.
async fn await_contract_cancelled(contract_id: ContractId, global_context: DynGlobalClientContext) {
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

/// Waits until a specific block height at which the contract will be able to be
/// reclaimed.
async fn await_contract_timeout(global_context: DynGlobalClientContext, timelock: u32) {
    loop {
        match global_context
            .module_api()
            .wait_block_height(u64::from(timelock))
            .await
        {
            Ok(()) => return,
            Err(error) => error!("Error waiting for block height: {timelock} {error:?}"),
        }

        sleep(RETRY_DELAY).await;
    }
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
    error_reason: String,
) -> LightningPayStateMachine {
    let contract_data = common.contract;
    let (refund_key, refund_input) = (
        contract_data.recovery_key,
        contract_data.contract_account.refund(),
    );

    let refund_client_input = ClientInput::<LightningInput> {
        input: refund_input,
        amount: contract_data.contract_account.amount,
        keys: vec![refund_key],
    };

    let (txid, out_points) = global_context
        .claim_inputs(
            dbtx,
            // The input of the refund tx is managed by this state machine, so no new state
            // machines need to be created
            ClientInputBundle::new_no_sm(vec![refund_client_input]),
        )
        .await
        .expect("Cannot claim input, additional funding needed");

    LightningPayStateMachine {
        common: old_state.common,
        state: LightningPayStates::Refund(LightningPayRefund {
            txid,
            out_points,
            error_reason,
        }),
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct LightningPayRefund {
    pub txid: TransactionId,
    pub out_points: Vec<OutPoint>,
    pub error_reason: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
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
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
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

    pub fn destination(&self) -> secp256k1::PublicKey {
        match self {
            PaymentData::Invoice(invoice) => bitcoin30_to_bitcoin32_secp256k1_pubkey(
                &invoice
                    .payee_pub_key()
                    .copied()
                    .unwrap_or_else(|| invoice.recover_payee_pub_key()),
            ),
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
            PaymentData::Invoice(invoice) => invoice.expires_at().map_or(u64::MAX, |t| t.as_secs()),
            PaymentData::PrunedInvoice(PrunedInvoice {
                expiry_timestamp, ..
            }) => *expiry_timestamp,
        }
    }
}
