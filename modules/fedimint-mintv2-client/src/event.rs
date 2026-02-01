use fedimint_core::Amount;
use fedimint_core::core::{ModuleKind, OperationId};
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use fedimint_mintv2_common::KIND;
use serde::{Deserialize, Serialize};

/// Event emitted when e-cash is sent out-of-band.
/// This is a final event - once e-cash is sent, the operation is complete.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SendPaymentEvent {
    pub operation_id: OperationId,
    pub amount: Amount,
}

impl Event for SendPaymentEvent {
    const MODULE: Option<ModuleKind> = Some(KIND);
    const KIND: EventKind = EventKind::from_static("payment-send");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event emitted when a receive (reissuance) operation is initiated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceivePaymentEvent {
    pub operation_id: OperationId,
    pub amount: Amount,
}

impl Event for ReceivePaymentEvent {
    const MODULE: Option<ModuleKind> = Some(KIND);
    const KIND: EventKind = EventKind::from_static("payment-receive");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Status of a receive (reissuance) operation.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum ReceivePaymentStatus {
    /// The reissuance was successful.
    Success,
    /// The reissuance was rejected.
    Rejected,
}

/// Event emitted when a receive (reissuance) operation reaches a final state.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceivePaymentUpdateEvent {
    pub operation_id: OperationId,
    pub status: ReceivePaymentStatus,
}

impl Event for ReceivePaymentUpdateEvent {
    const MODULE: Option<ModuleKind> = Some(KIND);
    const KIND: EventKind = EventKind::from_static("payment-receive-update");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}
