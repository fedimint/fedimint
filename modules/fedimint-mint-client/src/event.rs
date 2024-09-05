use fedimint_client::db::event_log::{Event, EventKind};
use fedimint_core::core::ModuleKind;
use fedimint_mint_common::{Nonce, KIND};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct NoteCreated {
    pub nonce: Nonce,
}

impl Event for NoteCreated {
    const MODULE: Option<ModuleKind> = Some(KIND);

    const KIND: EventKind = EventKind::from_static("note-created");
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct NoteSpent {
    pub nonce: Nonce,
}

impl Event for NoteSpent {
    const MODULE: Option<ModuleKind> = Some(KIND);

    const KIND: EventKind = EventKind::from_static("note-spent");
}
