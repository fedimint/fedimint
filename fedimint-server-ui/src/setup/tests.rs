use std::collections::BTreeSet;

use super::{restore_form_content, setup_choice_content, setup_error_message, setup_form_content};

#[test]
fn setup_form_targets_error_container() {
    let content = setup_form_content(&BTreeSet::new(), &BTreeSet::new()).into_string();

    assert!(content.contains(r##"hx-target="#setup-error""##));
    assert!(content.contains(r#"<div id="setup-error"></div>"#));
}

#[test]
fn setup_error_message_is_partial() {
    let content = setup_error_message("Invalid federation size").into_string();

    assert!(content.contains("Invalid federation size"));
    assert!(!content.contains("setup-form"));
}

#[test]
fn setup_choice_has_start_and_restore_options() {
    let content = setup_choice_content(None).into_string();

    assert!(content.contains("Start new Federation"));
    assert!(content.contains("Restore from backup"));
    assert!(!content.contains("multipart/form-data"));
}

#[test]
fn restore_form_has_upload_fields() {
    let content = restore_form_content(None).into_string();

    assert!(content.contains("multipart/form-data"));
    assert!(content.contains("Guardian Password"));
    assert!(content.contains("Restore Guardian"));
}
