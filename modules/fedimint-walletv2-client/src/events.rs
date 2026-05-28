use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
use fedimint_core::core::{ModuleKind, OperationId};
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use serde::{Deserialize, Serialize};

/// Event emitted when a pegout (send to onchain) operation is initiated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SendPaymentEvent {
    pub operation_id: OperationId,
    pub address: Address<NetworkUnchecked>,
    pub value: bitcoin::Amount,
    pub fee: bitcoin::Amount,
}

impl Event for SendPaymentEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_walletv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-send");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Status of a send (pegout) operation.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum SendPaymentStatus {
    /// The pegout was successful, includes the bitcoin transaction ID.
    Success(Txid),
    /// The pegout was aborted.
    Aborted,
}

/// Event emitted when a send (pegout) operation reaches a final state.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SendPaymentUpdateEvent {
    pub operation_id: OperationId,
    pub status: SendPaymentStatus,
}

impl Event for SendPaymentUpdateEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_walletv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-send-update");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event emitted when a receive (pegin) operation is initiated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceivePaymentEvent {
    pub operation_id: OperationId,
    pub value: bitcoin::Amount,
    pub fee: bitcoin::Amount,
    pub address: Address<NetworkUnchecked>,
    pub outpoint: Option<bitcoin::OutPoint>,
}

impl Event for ReceivePaymentEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_walletv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-receive");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Status of a receive (pegin) operation.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum ReceivePaymentStatus {
    /// The pegin was successful.
    Success,
    /// The pegin was aborted.
    Aborted,
}

/// Event emitted when a receive (pegin) operation reaches a final state.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceivePaymentUpdateEvent {
    pub operation_id: OperationId,
    pub status: ReceivePaymentStatus,
}

impl Event for ReceivePaymentUpdateEvent {
    const MODULE: Option<ModuleKind> = Some(fedimint_walletv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("payment-receive-update");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}
