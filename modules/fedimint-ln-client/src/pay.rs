use std::sync::Arc;
use std::time::Duration;

use fedimint_client::sm::{ClientSMDatabaseTransaction, OperationId, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::{Amount, TransactionId};
use fedimint_ln_common::contracts::outgoing::OutgoingContract;
use fedimint_ln_common::contracts::{ContractId, IdentifiableContract, Preimage};
use fedimint_ln_common::{LightningGateway, LightningInput};
use fedimint_wallet_client::api::WalletFederationApi;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use crate::api::LnFederationApi;
use crate::{LightningClientContext, LightningClientStateMachines};

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
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum LightningPayStates {
    CreatedOutgoingLnContract(LightningPayCreatedOutgoingLnContract),
    Canceled,
    Funded(LightningPayFunded),
    Success(String),
    Refundable(LightningPayRefundable),
    Refund(LightningPayRefund),
    Refunded(TransactionId),
    Failure(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningPayCommon {
    pub operation_id: OperationId,
    pub federation_id: FederationId,
    pub contract: OutgoingContractData,
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
        _context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            LightningPayStates::CreatedOutgoingLnContract(created_outgoing_ln_contract) => {
                created_outgoing_ln_contract.transitions(&self.common, global_context)
            }
            LightningPayStates::Canceled => {
                vec![]
            }
            LightningPayStates::Funded(funded) => funded.transitions(global_context.clone()),
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
        common: &LightningPayCommon,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningPayStateMachine>> {
        let txid = self.funding_txid;
        let contract_id = self.contract_id;
        let funded_common = common.clone();
        let success_context = global_context.clone();
        let gateway = self.gateway.clone();
        vec![StateTransition::new(
            Self::await_outgoing_contract_funded(funded_common.clone(), success_context, txid),
            move |_dbtx, result, old_state| {
                Box::pin(Self::transition_outgoing_contract_funded(
                    result,
                    old_state,
                    funded_common.clone(),
                    contract_id,
                    gateway.clone(),
                ))
            },
        )]
    }

    async fn await_outgoing_contract_funded(
        common: LightningPayCommon,
        global_context: DynGlobalClientContext,
        txid: TransactionId,
    ) -> Result<(), ()> {
        global_context
            .await_tx_accepted(common.operation_id, txid)
            .await
    }

    async fn transition_outgoing_contract_funded(
        result: Result<(), ()>,
        old_state: LightningPayStateMachine,
        common: LightningPayCommon,
        contract_id: ContractId,
        gateway: LightningGateway,
    ) -> LightningPayStateMachine {
        assert!(matches!(
            old_state.state,
            LightningPayStates::CreatedOutgoingLnContract(_)
        ));

        match result {
            Ok(_) => {
                // Success case: funding transaction is accepted
                let payload = PayInvoicePayload::new(common.federation_id, contract_id);
                LightningPayStateMachine {
                    common: old_state.common,
                    state: LightningPayStates::Funded(LightningPayFunded { payload, gateway }),
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
}

#[derive(Error, Debug, Serialize, Deserialize)]
enum GatewayPayError {
    #[error("Lightning Gateway failed to pay invoice")]
    GatewayInternalError,
}

impl LightningPayFunded {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningPayStateMachine>> {
        let gateway = self.gateway.clone();
        let payload = self.payload.clone();
        let contract_id = self.payload.contract_id;
        let timeout_context = global_context.clone();
        vec![
            StateTransition::new(
                // Wait for the result of the payment by the gateway
                Self::await_outgoing_contract_execution(gateway, payload),
                move |_dbtx, result, old_state| {
                    Box::pin(Self::transition_outgoing_contract_execution(
                        old_state,
                        timeout_context.clone(),
                        result,
                        contract_id,
                    ))
                },
            ),
            // wait for gatewayd for two minutes before timing out
            StateTransition::new(
                sleep(Duration::from_secs(120)),
                move |_dbtx, (), old_state| {
                    Box::pin(Self::transition_pay_timeout(
                        old_state,
                        global_context.clone(),
                        contract_id,
                    ))
                },
            ),
        ]
    }

    async fn await_outgoing_contract_execution(
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
            .map_err(|_| GatewayPayError::GatewayInternalError)?;

        if !response.status().is_success() {
            return Err(GatewayPayError::GatewayInternalError);
        }

        let preimage = response
            .text()
            .await
            .map_err(|_| GatewayPayError::GatewayInternalError)?;
        let length = preimage.len();
        Ok(preimage[1..length - 1].to_string())
    }

    async fn transition_pay_timeout(
        old_state: LightningPayStateMachine,
        global_context: DynGlobalClientContext,
        contract_id: ContractId,
    ) -> LightningPayStateMachine {
        // TODO: Retry contacting gateway

        let contract = global_context
            .api()
            .get_outgoing_contract(contract_id)
            .await;
        let timelock = match contract {
            Ok(contract) => contract.contract.timelock,
            Err(_) => {
                return LightningPayStateMachine {
                    common: old_state.common,
                    state: LightningPayStates::Failure(
                        "Failed to retrieve OutgoingContract".to_string(),
                    ),
                }
            }
        };

        LightningPayStateMachine {
            common: old_state.common,
            state: LightningPayStates::Refundable(LightningPayRefundable {
                contract_id,
                block_timelock: timelock,
            }),
        }
    }

    async fn transition_outgoing_contract_execution(
        old_state: LightningPayStateMachine,
        global_context: DynGlobalClientContext,
        result: Result<String, GatewayPayError>,
        contract_id: ContractId,
    ) -> LightningPayStateMachine {
        match result {
            Ok(preimage) => LightningPayStateMachine {
                common: old_state.common,
                state: LightningPayStates::Success(preimage),
            },
            Err(GatewayPayError::GatewayInternalError) => {
                let contract = global_context
                    .api()
                    .get_outgoing_contract(contract_id)
                    .await;
                let timelock = match contract {
                    Ok(contract) => contract.contract.timelock,
                    Err(_) => {
                        return LightningPayStateMachine {
                            common: old_state.common,
                            state: LightningPayStates::Failure(
                                "Failed to retrieve OutgoingContract".to_string(),
                            ),
                        }
                    }
                };

                LightningPayStateMachine {
                    common: old_state.common,
                    state: LightningPayStates::Refundable(LightningPayRefundable {
                        contract_id,
                        block_timelock: timelock,
                    }),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningPayRefundable {
    contract_id: ContractId,
    pub block_timelock: u32,
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

        let refund_txid = global_context.claim_input(dbtx, refund_client_input).await;

        LightningPayStateMachine {
            common: old_state.common,
            state: LightningPayStates::Refund(LightningPayRefund { refund_txid }),
        }
    }

    async fn await_contract_cancellable(
        contract_id: ContractId,
        global_context: DynGlobalClientContext,
    ) {
        // TODO: Remove polling
        loop {
            let contract = global_context
                .api()
                .get_outgoing_contract(contract_id)
                .await;
            if let Ok(contract) = contract {
                if contract.contract.cancelled {
                    return;
                }
            }

            sleep(Duration::from_secs(5)).await;
        }
    }

    async fn await_contract_timeout(global_context: DynGlobalClientContext, timelock: u32) {
        // TODO: Remove polling
        loop {
            let consensus_block_height = global_context
                .api()
                .fetch_consensus_block_height()
                .await
                .map_err(|_| anyhow::anyhow!("ApiError"));

            if let Ok(current_block_height) = consensus_block_height {
                if timelock as u64 <= current_block_height {
                    return;
                }
            }

            sleep(Duration::from_secs(5)).await;
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningPayRefund {
    refund_txid: TransactionId,
}

impl LightningPayRefund {
    fn transitions(
        &self,
        common: &LightningPayCommon,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningPayStateMachine>> {
        let refund_txid = self.refund_txid;
        vec![StateTransition::new(
            Self::await_refund_success(common.clone(), global_context.clone(), refund_txid),
            move |_dbtx, result, old_state| {
                Box::pin(Self::transition_refund_success(
                    result,
                    old_state,
                    refund_txid,
                ))
            },
        )]
    }

    async fn await_refund_success(
        common: LightningPayCommon,
        global_context: DynGlobalClientContext,
        refund_txid: TransactionId,
    ) -> Result<(), ()> {
        global_context
            .await_tx_accepted(common.operation_id, refund_txid)
            .await
    }

    async fn transition_refund_success(
        result: Result<(), ()>,
        old_state: LightningPayStateMachine,
        refund_txid: TransactionId,
    ) -> LightningPayStateMachine {
        match result {
            Ok(_) => {
                // Refund successful
                LightningPayStateMachine {
                    common: old_state.common,
                    state: LightningPayStates::Refunded(refund_txid),
                }
            }
            Err(_) => {
                // Refund failure
                LightningPayStateMachine {
                    common: old_state.common,
                    state: LightningPayStates::Failure(format!(
                        "Refund Transaction was rejected. Txid: {refund_txid}"
                    )),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decodable, Encodable)]
pub struct PayInvoicePayload {
    pub federation_id: FederationId,
    pub contract_id: ContractId,
}

impl PayInvoicePayload {
    pub fn new(federation_id: FederationId, contract_id: ContractId) -> Self {
        Self {
            contract_id,
            federation_id,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct OutgoingContractData {
    pub recovery_key: bitcoin::KeyPair,
    pub contract_account: OutgoingContractAccount,
}

#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize)]
pub struct OutgoingContractAccount {
    pub amount: Amount,
    pub contract: OutgoingContract,
}

impl OutgoingContractAccount {
    pub fn claim(&self, preimage: Preimage) -> LightningInput {
        LightningInput {
            contract_id: self.contract.contract_id(),
            amount: self.amount,
            witness: Some(preimage),
        }
    }

    pub fn refund(&self) -> LightningInput {
        LightningInput {
            contract_id: self.contract.contract_id(),
            amount: self.amount,
            witness: None,
        }
    }
}
