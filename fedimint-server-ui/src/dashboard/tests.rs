use axum::http::HeaderValue;
use chrono::NaiveDate;

use super::guardian_backup_filename;

#[test]
fn backup_filename_contains_date_and_peer_name() {
    let date = NaiveDate::from_ymd_opt(2026, 1, 2).unwrap();
    assert_eq!(
        guardian_backup_filename(date, "Alice's Node_2-west"),
        "2026-01-02-Alice_s_Node_2-west-guardian-backup.tar"
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
fn backup_filename_bounds_peer_name_length() {
    let date = NaiveDate::from_ymd_opt(2026, 1, 2).unwrap();
    assert_eq!(
        guardian_backup_filename(date, &"a".repeat(1_000)),
        format!("2026-01-02-{}-guardian-backup.tar", "a".repeat(64))
    );
}
