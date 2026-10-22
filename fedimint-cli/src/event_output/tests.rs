use fedimint_core::core::ModuleKind;
use fedimint_eventlog::{EventKind, EventLogEntry, EventLogId, EventLogModule, EventLogTrimableId};
use serde_json::json;

use super::event_to_json;

#[test]
fn render_json_payload_and_module_in_both_id_spaces() {
    let event = EventLogEntry {
        kind: EventKind::from_static("test"),
        module: Some(EventLogModule {
            kind: ModuleKind::from_static_str("mint"),
            id: 7,
        }),
        ts_usecs: 123,
        payload: br#"{"amount":42}"#.to_vec(),
    };
    let expected = json!({
        "id": 3, "kind": "test", "module_kind": "mint",
        "module_id": 7, "ts": 123, "payload": {"amount": 42},
    });
    assert_eq!(
        event_to_json(EventLogId::LOG_START.saturating_add(3), &event),
        expected
    );
    assert_eq!(event_to_json(EventLogTrimableId::from(3), &event), expected);
}

#[test]
fn render_binary_payload_as_hex_and_absent_module_as_null() {
    let event = EventLogEntry {
        kind: EventKind::from_static("binary"),
        module: None,
        ts_usecs: 456,
        payload: vec![0xff, 0, 0x42],
    };
    assert_eq!(
        event_to_json(EventLogId::LOG_START.saturating_add(8), &event),
        json!({
            "id": 8, "kind": "binary", "module_kind": null,
            "module_id": null, "ts": 456, "payload": "ff0042",
        })
    );
}
