use fedimint_core::core::{ModuleKind, OperationId};
use fedimint_core::Amount;
use fedimint_eventlog::{Event, EventKind};
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::ContractId;
use serde::{Deserialize, Serialize};

use super::pay::OutgoingPaymentError;

/// LNv1 event that is emitted when an outgoing payment attempt is initiated.
#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentStarted {
    /// The contract ID that uniquely identifies the outgoing contract.
    pub contract_id: ContractId,

    /// The amount of the invoice that is being paid.
    pub invoice_amount: Amount,

    /// The operation ID of the outgoing payment
    pub operation_id: OperationId,
}

impl Event for OutgoingPaymentStarted {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-started");
}

/// LNv1 event that is emitted when an outgoing payment attempt has succeeded.
#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentSucceeded {
    /// LNv1 outgoing contract
    pub outgoing_contract: OutgoingContractAccount,

    /// The contract ID that uniquely identifies the outgoing contract.
    pub contract_id: ContractId,

    /// The preimage acquired from successfully paying the invoice.
    pub preimage: String,
}

impl Event for OutgoingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-succeeded");
}

/// LNv1 event that is emitted when an outgoing payment attempt has failed.
#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentFailed {
    /// LNv1 outgoing contract
    pub outgoing_contract: OutgoingContractAccount,

    /// The contract ID that uniquely identifies the outgoing contract.
    pub contract_id: ContractId,

    /// The reason the outgoing payment failed.
    pub error: OutgoingPaymentError,
}

impl Event for OutgoingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-failed");
}

/// LNv1 event that is emitted when an incoming payment attempt has started.
#[derive(Serialize, Deserialize)]
pub struct IncomingPaymentStarted {
    /// The contract ID that uniquely identifies the incoming contract.
    pub contract_id: ContractId,

    /// The payment hash of the invoice that is being paid.
    pub payment_hash: bitcoin::hashes::sha256::Hash,

    /// The amount specified in the invoice.
    pub invoice_amount: Amount,

    /// The amount offered in the contract.
    pub contract_amount: Amount,

    /// The operation ID of the outgoing payment
    pub operation_id: OperationId,
}

impl Event for IncomingPaymentStarted {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("incoming-payment-started");
}

/// LNv1 event that is emitted when an incoming payment attempt was successful.
#[derive(Serialize, Deserialize)]
pub struct IncomingPaymentSucceeded {
    /// The payment hash of the invoice that was paid.
    pub payment_hash: bitcoin::hashes::sha256::Hash,

    /// The decrypted preimage that was acquired from the federation.
    pub preimage: String,
}

impl Event for IncomingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("incoming-payment-succeeded");
}

/// LNv1 event that is emitted when an incoming payment attempt has failed.
#[derive(Serialize, Deserialize)]
pub struct IncomingPaymentFailed {
    /// The payment hash of the invoice that failed to be paid.
    pub payment_hash: bitcoin::hashes::sha256::Hash,

    /// The reason the incoming payment attempt failed.
    pub error: String,
}

impl Event for IncomingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("incoming-payment-failed");
}

/// LNv1 event that is emitted when a preimage was successfully revealed to the
/// Lightning Network.
#[derive(Serialize, Deserialize)]
pub struct CompleteLightningPaymentSucceeded {
    /// The payment hash of the payment.
    pub payment_hash: bitcoin::hashes::sha256::Hash,
}

impl Event for CompleteLightningPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("complete-lightning-payment-succeeded");
}
