use fedimint_core::Amount;
use fedimint_core::core::{ModuleKind, OperationId};
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use serde::{Deserialize, Serialize};

use crate::LightningInvoice;

/// Event emitted when a send operation is created.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SendPaymentEvent {
    pub operation_id: OperationId,
    pub amount: Amount,
    pub invoice: Option<LightningInvoice>,
}

impl Event for SendPaymentEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-send");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Status of a send operation.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum SendPaymentStatus {
    /// The payment was successful, includes the preimage as proof of payment.
    Success([u8; 32]),
    /// The payment has been refunded.
    Refunded,
}

/// Event emitted when a send operation reaches a final state.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SendPaymentUpdateEvent {
    pub operation_id: OperationId,
    pub status: SendPaymentStatus,
}

impl Event for SendPaymentUpdateEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-send-update");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event emitted when a receive operation successfully completes and
/// transitions to the claiming state.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceivePaymentEvent {
    pub operation_id: OperationId,
    pub amount: Amount,
}

impl Event for ReceivePaymentEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-receive");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Union of all Lightning payment events.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LightningPaymentEvent {
    Send(SendPaymentEvent, u64),
    SendUpdate(SendPaymentUpdateEvent, u64),
    Receive(ReceivePaymentEvent, u64),
}
