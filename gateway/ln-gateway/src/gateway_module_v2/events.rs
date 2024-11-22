use std::time::SystemTime;

use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleKind;
use fedimint_core::Amount;
use fedimint_eventlog::{Event, EventKind};
use fedimint_lnv2_common::contracts::{Commitment, OutgoingContract, PaymentImage};
use serde::{Deserialize, Serialize};
use serde_millis;

use super::send_sm::Cancelled;

/// Event that is emitted when an outgoing payment attempt is initiated.
#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentStarted {
    /// The timestamp that the operation begins, including the API calls to the
    /// federation to get the consensus block height.
    #[serde(with = "serde_millis")]
    pub operation_start: SystemTime,

    /// The outgoing contract for this payment.
    pub outgoing_contract: OutgoingContract,

    /// The minimum amount that must be escrowed for the payment (includes the
    /// gateway's fee)
    pub min_contract_amount: Amount,

    /// The amount requested in the invoice.
    pub invoice_amount: Amount,

    /// The max delay of the payment in blocks.
    pub max_delay: u64,
}

impl Event for OutgoingPaymentStarted {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-started");
}

/// Event that is emitted when an outgoing payment attempt has succeeded.
#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentSucceeded {
    /// The payment image of the invoice that was paid.
    pub payment_image: PaymentImage,

    /// The target federation ID if a swap was performed, otherwise `None`.
    pub target_federation: Option<FederationId>,
}

impl Event for OutgoingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-succeeded");
}

/// Event that is emitted when an outgoing payment attempt has failed.
#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentFailed {
    /// The payment image of the invoice that failed.
    pub payment_image: PaymentImage,

    /// The reason the outgoing payment was cancelled.
    pub error: Cancelled,
}

impl Event for OutgoingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-failed");
}

/// Event that is emitted when an incoming payment attempt has started. Includes
/// both internal swaps and outside LN payments.
#[derive(Serialize, Deserialize)]
pub struct IncomingPaymentStarted {
    /// The timestamp that the operation begins, including any metadata checks
    /// before the state machine has spawned.
    #[serde(with = "serde_millis")]
    pub operation_start: SystemTime,

    /// The commitment for the incoming contract.
    pub incoming_contract_commitment: Commitment,

    /// The amount requested in the invoice.
    pub invoice_amount: Amount,
}

impl Event for IncomingPaymentStarted {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("incoming-payment-started");
}

/// Event that is emitted when an incoming payment attempt has succeeded.
/// Includes both internal swaps and outside LN payments.
#[derive(Serialize, Deserialize)]
pub struct IncomingPaymentSucceeded {
    /// The payment image of the invoice that was paid.
    pub payment_image: PaymentImage,
}

impl Event for IncomingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("incoming-payment-succeeded");
}

/// Event that is emitted when an incoming payment attempt has failed.
#[derive(Serialize, Deserialize)]
pub struct IncomingPaymentFailed {
    /// The payment image of the invoice that failed
    pub payment_image: PaymentImage,

    /// The reason the incoming payment failed
    pub error: String,
}

impl Event for IncomingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("incoming-payment-failed");
}

/// Event that is emitted when a preimage is revealed to the Lightning network.
/// Only emitted for payments that are received from an external Lightning node,
/// not internal swaps.
#[derive(Serialize, Deserialize)]
pub struct CompleteLightningPaymentSucceeded {
    /// The payment image of the invoice that was paid.
    pub payment_image: PaymentImage,
}

impl Event for CompleteLightningPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("complete-lightning-payment-succeeded");
}
