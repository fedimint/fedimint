use fedimint_core::Amount;
use fedimint_core::core::{Account, ModuleKind, OperationId};
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use serde::{Deserialize, Serialize};

/// Event emitted when a send operation is created.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SendPaymentEvent {
    pub operation_id: OperationId,
    pub amount: Amount,
    pub fee: Amount,
    /// Balance the contract was funded from. Defaulted rather than required,
    /// so entries written before accounts existed still decode — they can only
    /// have been the one account there was.
    #[serde(default = "Account::primary")]
    pub account: Account,
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
    /// Balance the operation acts on, repeated from the initiating event so a
    /// consumer can filter the final state by account without joining on the
    /// operation id. Defaulted so entries written before accounts existed
    /// still decode.
    #[serde(default = "Account::primary")]
    pub account: Account,
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
    /// Absolute fee paid to the gateway. Defaults to zero for events recorded
    /// before this field was added.
    #[serde(default)]
    pub fee: Amount,
    /// Balance the claimed contract is credited to. See
    /// [`SendPaymentEvent::account`] for why it is defaulted.
    #[serde(default = "Account::primary")]
    pub account: Account,
}

impl Event for ReceivePaymentEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-receive");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}
