use std::time::Duration;

use fedimint_core::Amount;
use fedimint_core::core::{ModuleKind, OperationId};
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use fedimint_mint_common::{KIND, Nonce};
use serde::{Deserialize, Serialize};

/// Event that is emitted when a note is created.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct NoteCreated {
    /// The nonce of the note
    pub nonce: Nonce,
}

impl Event for NoteCreated {
    const MODULE: Option<ModuleKind> = Some(KIND);

    const KIND: EventKind = EventKind::from_static("note-created");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when a note is spent.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct NoteSpent {
    /// The nonce of the note
    pub nonce: Nonce,
}

impl Event for NoteSpent {
    const MODULE: Option<ModuleKind> = Some(KIND);

    const KIND: EventKind = EventKind::from_static("note-spent");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when ecash is spent out of band
#[derive(Serialize, Deserialize)]
pub struct OOBNotesSpent {
    /// The requested amount to spend out of band
    pub requested_amount: Amount,

    /// The actual amount of ecash spent
    pub spent_amount: Amount,

    /// The timeout before attempting to refund
    pub timeout: Duration,

    /// Boolean that indicates if the invite code was included in the note
    /// serialization
    pub include_invite: bool,
}

impl Event for OOBNotesSpent {
    const MODULE: Option<ModuleKind> = Some(KIND);

    const KIND: EventKind = EventKind::from_static("oob-notes-spent");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when out of band ecash is reissued
#[derive(Serialize, Deserialize)]
pub struct OOBNotesReissued {
    /// The amount of out of band ecash being reissued
    pub amount: Amount,
}

impl Event for OOBNotesReissued {
    const MODULE: Option<ModuleKind> = Some(KIND);
    const KIND: EventKind = EventKind::from_static("oob-notes-reissued");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when ecash is reissued as part of a recovery process
#[derive(Serialize, Deserialize)]
pub struct RecoveryReissuanceStarted {
    /// The amount of ecash that was recovered and is being reissued
    pub amount: Amount,
    /// The operation id of the recovery process
    pub operation_id: OperationId,
}

impl Event for RecoveryReissuanceStarted {
    const MODULE: Option<ModuleKind> = Some(KIND);
    const KIND: EventKind = EventKind::from_static("recovered-notes-reissued");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event emitted when e-cash is sent out-of-band.
/// This is a final event - once e-cash is sent, the operation is complete.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SendPaymentEvent {
    pub operation_id: OperationId,
    pub amount: Amount,
    pub oob_notes: String,
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
