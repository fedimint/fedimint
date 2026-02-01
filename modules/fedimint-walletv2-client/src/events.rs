use bitcoin::Txid;
use fedimint_core::core::{ModuleKind, OperationId};
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use serde::{Deserialize, Serialize};

/// Event emitted when a peg-out (send to onchain) operation is initiated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SendPaymentEvent {
    pub operation_id: OperationId,
    pub amount: bitcoin::Amount,
    pub fee: bitcoin::Amount,
}

impl Event for SendPaymentEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_walletv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-send");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Status of a send (peg-out) operation.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum SendPaymentStatus {
    /// The peg-out was successful, includes the bitcoin transaction ID.
    Success(Txid),
    /// The peg-out was aborted.
    Aborted,
}

/// Event emitted when a send (peg-out) operation reaches a final state.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SendPaymentStatusEvent {
    pub operation_id: OperationId,
    pub status: SendPaymentStatus,
}

impl Event for SendPaymentStatusEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_walletv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-send-status");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event emitted when a receive (peg-in) operation is initiated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceivePaymentEvent {
    pub operation_id: OperationId,
    pub amount: bitcoin::Amount,
    pub fee: bitcoin::Amount,
}

impl Event for ReceivePaymentEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_walletv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-receive");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Status of a receive (peg-in) operation.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum ReceivePaymentStatus {
    /// The peg-in was successful.
    Success,
    /// The peg-in was aborted.
    Aborted,
}

/// Event emitted when a receive (peg-in) operation reaches a final state.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceivePaymentStatusEvent {
    pub operation_id: OperationId,
    pub status: ReceivePaymentStatus,
}

impl Event for ReceivePaymentStatusEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_walletv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-receive-status");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}
