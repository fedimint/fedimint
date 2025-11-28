//! State machines for the ecash migration client module

use fedimint_api_client::api::{DynModuleApi, FederationApiExt as _};
use fedimint_client_module::sm::{DynState, State, StateTransition};
use fedimint_client_module::{DynGlobalClientContext, sm_enum_variant_translation};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_ecash_migration_common::TransferId;
use fedimint_ecash_migration_common::api::GET_TRANSFER_ID_ENDPOINT;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::EcashMigrationClientContext;

/// State machine for ecash migration operations
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum EcashMigrationStateMachine {
    /// State machine for registering a liability transfer
    RegisterTransfer(RegisterTransferStateMachine),
    /// State machine for funding a liability transfer
    FundTransfer(FundTransferStateMachine),
    /// State machine for redeeming origin ecash
    RedeemOriginEcash(RedeemOriginEcashStateMachine),
}

impl State for EcashMigrationStateMachine {
    type ModuleContext = EcashMigrationClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            EcashMigrationStateMachine::RegisterTransfer(sm) => {
                sm_enum_variant_translation!(
                    sm.transitions(context, global_context),
                    EcashMigrationStateMachine::RegisterTransfer
                )
            }
            EcashMigrationStateMachine::FundTransfer(sm) => {
                sm_enum_variant_translation!(
                    sm.transitions(global_context),
                    EcashMigrationStateMachine::FundTransfer
                )
            }
            EcashMigrationStateMachine::RedeemOriginEcash(sm) => {
                sm_enum_variant_translation!(
                    sm.transitions(global_context),
                    EcashMigrationStateMachine::RedeemOriginEcash
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            EcashMigrationStateMachine::RegisterTransfer(sm) => sm.operation_id(),
            EcashMigrationStateMachine::FundTransfer(sm) => sm.operation_id(),
            EcashMigrationStateMachine::RedeemOriginEcash(sm) => sm.operation_id(),
        }
    }
}

impl IntoDynInstance for EcashMigrationStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

/// Common data for the register liability transfer state machine
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct RegisterTransferCommon {
    pub operation_id: OperationId,
    pub txid: TransactionId,
    pub out_point: OutPoint,
}

/// State machine for registering a liability transfer
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct RegisterTransferStateMachine {
    pub common: RegisterTransferCommon,
    pub state: RegisterTransferStates,
}

impl RegisterTransferStateMachine {
    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }

    fn transitions(
        &self,
        context: &EcashMigrationClientContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            RegisterTransferStates::Created => {
                Self::created_transitions(context, global_context, self.common.clone())
            }
            RegisterTransferStates::Aborted(_) | RegisterTransferStates::Success(_) => vec![],
        }
    }

    fn created_transitions(
        context: &EcashMigrationClientContext,
        global_context: &DynGlobalClientContext,
        common: RegisterTransferCommon,
    ) -> Vec<StateTransition<Self>> {
        let global_ctx = global_context.clone();
        let module_api = context.module_api.clone();

        vec![
            // Check if transaction was rejected
            StateTransition::new(
                Self::await_tx_rejected(global_context.clone(), common.txid),
                |_dbtx, (), old_state| {
                    Box::pin(async move { Self::transition_tx_rejected(old_state) })
                },
            ),
            // Check for transaction acceptance and fetch transfer ID
            StateTransition::new(
                Self::await_tx_accepted_and_get_transfer_id(global_ctx, module_api, common),
                |_dbtx, transfer_id, old_state| {
                    Box::pin(async move { Self::transition_tx_accepted(transfer_id, old_state) })
                },
            ),
        ]
    }

    async fn await_tx_rejected(global_context: DynGlobalClientContext, txid: TransactionId) {
        if global_context.await_tx_accepted(txid).await.is_err() {
            return;
        }
        std::future::pending::<()>().await;
    }

    fn transition_tx_rejected(old_state: Self) -> Self {
        Self {
            common: old_state.common,
            state: RegisterTransferStates::Aborted(RegisterTransferAborted {
                reason: "Transaction was rejected".to_string(),
            }),
        }
    }

    async fn await_tx_accepted_and_get_transfer_id(
        global_context: DynGlobalClientContext,
        module_api: DynModuleApi,
        common: RegisterTransferCommon,
    ) -> TransferId {
        // Wait for transaction to be accepted (this retries until success or rejection)
        // If rejected, the other transition will fire
        if global_context.await_tx_accepted(common.txid).await.is_err() {
            // Transaction was rejected, hang forever since the rejection
            // transition will take precedence
            std::future::pending::<()>().await;
        }

        // Fetch the transfer ID from the server
        module_api
            .request_current_consensus_retry(
                GET_TRANSFER_ID_ENDPOINT.to_string(),
                ApiRequestErased::new(common.out_point),
            )
            .await
    }

    fn transition_tx_accepted(transfer_id: TransferId, old_state: Self) -> Self {
        Self {
            common: old_state.common,
            state: RegisterTransferStates::Success(RegisterTransferSuccess { transfer_id }),
        }
    }
}

/// States of the register transfer state machine
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum RegisterTransferStates {
    /// Transfer creation transaction submitted, waiting for confirmation
    Created,
    /// Transfer creation transaction was rejected
    Aborted(RegisterTransferAborted),
    /// Transfer successfully registered with the federation
    Success(RegisterTransferSuccess),
}

/// Transfer creation was aborted
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct RegisterTransferAborted {
    pub reason: String,
}

/// Transfer registration failed
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct RegisterTransferFailed {
    pub error: String,
}

/// Transfer successfully registered
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct RegisterTransferSuccess {
    pub transfer_id: TransferId,
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum EcashMigrationError {
    #[error("Ecash migration module had an internal error")]
    EcashMigrationInternalError,
}

/// State updates for register transfer operation that can be observed by
/// clients
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum RegisterTransferState {
    /// Transaction submitted, waiting for confirmation
    Created,
    /// Transaction accepted, fetching transfer ID
    TxAccepted,
    /// Transfer registration completed successfully
    Success { transfer_id: TransferId },
    /// Transfer registration failed
    Failed { error: String },
}

// ============================================================================
// Fund Transfer State Machine
// ============================================================================

/// Common data for the fund transfer state machine
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct FundTransferCommon {
    pub operation_id: OperationId,
    pub txid: TransactionId,
    pub transfer_id: TransferId,
    pub amount: Amount,
}

/// State machine for funding a liability transfer
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct FundTransferStateMachine {
    pub common: FundTransferCommon,
    pub state: FundTransferStates,
}

impl FundTransferStateMachine {
    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }

    fn transitions(&self, global_context: &DynGlobalClientContext) -> Vec<StateTransition<Self>> {
        match &self.state {
            FundTransferStates::Created => {
                Self::created_transitions(global_context, self.common.clone())
            }
            FundTransferStates::Aborted(_) | FundTransferStates::Success(_) => vec![],
        }
    }

    #[allow(clippy::needless_pass_by_value)] // common is captured by async closures
    fn created_transitions(
        global_context: &DynGlobalClientContext,
        common: FundTransferCommon,
    ) -> Vec<StateTransition<Self>> {
        vec![
            // Check if transaction was rejected
            StateTransition::new(
                Self::await_tx_rejected(global_context.clone(), common.txid),
                |_dbtx, (), old_state| {
                    Box::pin(async move { Self::transition_tx_rejected(old_state) })
                },
            ),
            // Check for transaction acceptance
            StateTransition::new(
                Self::await_tx_accepted(global_context.clone(), common.clone()),
                |_dbtx, (), old_state| {
                    Box::pin(async move { Self::transition_tx_accepted(old_state) })
                },
            ),
        ]
    }

    async fn await_tx_rejected(global_context: DynGlobalClientContext, txid: TransactionId) {
        if global_context.await_tx_accepted(txid).await.is_err() {
            return;
        }
        std::future::pending::<()>().await;
    }

    fn transition_tx_rejected(old_state: Self) -> Self {
        Self {
            common: old_state.common,
            state: FundTransferStates::Aborted(FundTransferAborted {
                reason: "Transaction was rejected".to_string(),
            }),
        }
    }

    async fn await_tx_accepted(global_context: DynGlobalClientContext, common: FundTransferCommon) {
        // Wait for transaction to be accepted
        if global_context.await_tx_accepted(common.txid).await.is_err() {
            // Transaction was rejected, hang forever since the rejection
            // transition will take precedence
            std::future::pending::<()>().await;
        }
    }

    #[allow(clippy::needless_pass_by_value)] // state machine transition signature
    fn transition_tx_accepted(old_state: Self) -> Self {
        Self {
            common: old_state.common.clone(),
            state: FundTransferStates::Success(FundTransferSuccess {
                transfer_id: old_state.common.transfer_id,
                amount: old_state.common.amount,
            }),
        }
    }
}

/// States of the fund transfer state machine
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum FundTransferStates {
    /// Fund liability transfer transaction submitted, waiting for confirmation
    Created,
    /// Fund liability transfer transaction was rejected
    Aborted(FundTransferAborted),
    /// Fund liability transfer completed successfully
    Success(FundTransferSuccess),
}

/// Fund liability transfer was aborted
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct FundTransferAborted {
    pub reason: String,
}

/// Fund liability transfer completed successfully
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct FundTransferSuccess {
    pub transfer_id: TransferId,
    pub amount: Amount,
}

/// State updates for fund liability transfer operation that can be observed by
/// clients
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum FundTransferState {
    /// Transaction submitted, waiting for confirmation
    Created,
    /// Fund liability transfer completed successfully
    Success {
        transfer_id: TransferId,
        amount: Amount,
    },
    /// Fund liability transfer failed
    Failed { error: String },
}

// ============================================================================
// Redeem Origin Ecash State Machine
// ============================================================================

/// Common data for the redeem origin ecash state machine
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct RedeemOriginEcashCommon {
    pub operation_id: OperationId,
    pub txid: TransactionId,
    pub transfer_id: TransferId,
    pub amount: Amount,
}

/// State machine for redeeming origin federation ecash
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct RedeemOriginEcashStateMachine {
    pub common: RedeemOriginEcashCommon,
    pub state: RedeemOriginEcashStates,
}

impl RedeemOriginEcashStateMachine {
    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }

    fn transitions(&self, global_context: &DynGlobalClientContext) -> Vec<StateTransition<Self>> {
        match &self.state {
            RedeemOriginEcashStates::Created => {
                Self::created_transitions(global_context, self.common.clone())
            }
            RedeemOriginEcashStates::Aborted(_) | RedeemOriginEcashStates::Success => vec![],
        }
    }

    #[allow(clippy::needless_pass_by_value)] // common is captured by async closures
    fn created_transitions(
        global_context: &DynGlobalClientContext,
        common: RedeemOriginEcashCommon,
    ) -> Vec<StateTransition<Self>> {
        vec![
            // Check if transaction was rejected
            StateTransition::new(
                Self::await_tx_rejected(global_context.clone(), common.txid),
                |_dbtx, (), old_state| {
                    Box::pin(async move { Self::transition_tx_rejected(old_state) })
                },
            ),
            // Check for transaction acceptance
            StateTransition::new(
                Self::await_tx_accepted(global_context.clone(), common.clone()),
                |_dbtx, (), old_state| {
                    Box::pin(async move { Self::transition_tx_accepted(old_state) })
                },
            ),
        ]
    }

    async fn await_tx_rejected(global_context: DynGlobalClientContext, txid: TransactionId) {
        if global_context.await_tx_accepted(txid).await.is_err() {
            return;
        }
        std::future::pending::<()>().await;
    }

    fn transition_tx_rejected(old_state: Self) -> Self {
        Self {
            common: old_state.common,
            state: RedeemOriginEcashStates::Aborted("Transaction was rejected".to_string()),
        }
    }

    async fn await_tx_accepted(
        global_context: DynGlobalClientContext,
        common: RedeemOriginEcashCommon,
    ) {
        // Wait for transaction to be accepted
        if global_context.await_tx_accepted(common.txid).await.is_err() {
            // Transaction was rejected, hang forever since the rejection
            // transition will take precedence
            std::future::pending::<()>().await;
        }
    }

    fn transition_tx_accepted(old_state: Self) -> Self {
        Self {
            common: old_state.common,
            state: RedeemOriginEcashStates::Success,
        }
    }
}

/// States of the redeem origin ecash state machine
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum RedeemOriginEcashStates {
    /// Redeem transaction submitted, waiting for confirmation
    Created,
    /// Redeem transaction was rejected (contains error message)
    Aborted(String),
    /// Redeem completed successfully (`transfer_id` and amount are in common)
    Success,
}

/// State updates for redeem origin ecash operation that can be observed by
/// clients
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum RedeemOriginEcashState {
    /// Transaction submitted, waiting for confirmation
    Created,
    /// Redeem completed successfully
    Success {
        transfer_id: TransferId,
        amount: Amount,
    },
    /// Redeem failed
    Failed { error: String },
}
