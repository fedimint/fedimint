use std::time::Duration;

use fedimint_core::core::ModuleKind;
use fedimint_core::Amount;
use fedimint_eventlog::{Event, EventKind};
use fedimint_mint_common::{Nonce, KIND};
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
}
