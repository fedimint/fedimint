use serde_json::json;

use super::{general, resolve_federation_name};

#[test]
fn meta_name_takes_precedence_over_legacy_name() {
    assert_eq!(
        resolve_federation_name(
            Some(&json!({"federation_name": "Updated name"})),
            Some("Legacy name".to_owned()),
        ),
        Some("Updated name".to_owned())
    );
}

#[test]
fn missing_or_invalid_meta_name_falls_back_to_legacy_name() {
    for meta in [None, Some(json!({})), Some(json!({"federation_name": 42}))] {
        assert_eq!(
            resolve_federation_name(meta.as_ref(), Some("Legacy name".to_owned())),
            Some("Legacy name".to_owned())
        );
        assert_eq!(resolve_federation_name(meta.as_ref(), None), None);
    }
}

#[test]
fn unnamed_federation_has_placeholder() {
    let html = general::render(None, 0, &Default::default()).into_string();
    assert!(html.contains("Federation name not set"));
}
