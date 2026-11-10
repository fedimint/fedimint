#[cfg(test)]
mod tests;

use fedimint_eventlog::EventLogEntry;
use serde::Serialize;
use serde_json::{Value, json};

/// Render either event-log ID space with the same JSON and binary-payload
/// fallback.
pub(super) fn event_to_json(id: impl Serialize, event: &EventLogEntry) -> Value {
    let module_id = event.module.as_ref().map(|module| module.id);
    let module_kind = event.module.as_ref().map(|module| module.kind.clone());
    json!({
        "id": id,
        "kind": event.kind,
        "module_kind": module_kind,
        "module_id": module_id,
        "ts": event.ts_usecs,
        "payload": serde_json::from_slice::<Value>(&event.payload)
            .unwrap_or_else(|_| Value::String(hex::encode(&event.payload))),
    })
}
