use axum::http::HeaderValue;
use chrono::NaiveDate;
use serde_json::json;

use super::{general, guardian_backup_filename, resolve_federation_name};

#[test]
fn backup_filename_contains_date_and_peer_name() {
    let date = NaiveDate::from_ymd_opt(2026, 1, 2).unwrap();
    assert_eq!(
        guardian_backup_filename(date, "Alice's Node_2-west"),
        "2026-01-02-Alice_s_Node_2-west-guardian-backup.tar"
    );
}

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
fn backup_filename_sanitizes_unsafe_names() {
    let date = NaiveDate::from_ymd_opt(2026, 1, 2).unwrap();
    for (name, expected) in [
        ("", "guardian"),
        ("../\\\";\r\n\0💾", "guardian"),
        ("---___", "guardian"),
        ("../../Alice\\Bob", "Alice_Bob"),
        ("Alice\";\r\nX-Evil: yes", "Alice____X-Evil__yes"),
        ("München 東京", "M_nchen"),
    ] {
        let filename = guardian_backup_filename(date, name);
        assert_eq!(
            filename,
            format!("2026-01-02-{expected}-guardian-backup.tar")
        );
        assert!(
            filename
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        );
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).unwrap();
    }
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
fn backup_filename_bounds_peer_name_length() {
    let date = NaiveDate::from_ymd_opt(2026, 1, 2).unwrap();
    assert_eq!(
        guardian_backup_filename(date, &"a".repeat(1_000)),
        format!("2026-01-02-{}-guardian-backup.tar", "a".repeat(64))
    );
}

#[test]
fn unnamed_federation_has_placeholder() {
    let html = general::render(None, 0, &Default::default()).into_string();
    assert!(html.contains("Federation name not set"));
}
