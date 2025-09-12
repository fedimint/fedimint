use fedimint_core::core::ModuleKind;
use fedimint_core::secp256k1::PublicKey;
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use fedimint_mintv2_common::KIND;
use serde::{Deserialize, Serialize};

/// Event that is emitted when a note is created.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct NoteCreated {
    pub nonce: PublicKey,
}

impl Event for NoteCreated {
    const MODULE: Option<ModuleKind> = Some(KIND);

    const KIND: EventKind = EventKind::from_static("note-created");

    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when a note is spent.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct NoteSpent {
    pub nonce: PublicKey,
}

impl Event for NoteSpent {
    const MODULE: Option<ModuleKind> = Some(KIND);

    const KIND: EventKind = EventKind::from_static("note-spent");

    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}
