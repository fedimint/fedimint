use serde_json::json;

use super::{Lnv1RegistryEvidenceV1, Lnv1RegistryState};

#[test]
fn wire_version_and_shape_are_enforced() {
    let current = serde_json::to_value(Lnv1RegistryEvidenceV1::no_registrations())
        .expect("serialization must work");
    assert_eq!(
        current,
        json!({
            "protocol_version": 1,
            "registrations": [],
            "state": "no_registrations"
        })
    );
    let mut additive = current.clone();
    additive
        .as_object_mut()
        .expect("snapshot is an object")
        .insert("future_optional_field".to_owned(), json!(true));
    assert!(serde_json::from_value::<Lnv1RegistryEvidenceV1>(additive).is_ok());

    for invalid in [
        json!({
            "protocol_version": 2,
            "registrations": [],
            "state": "no_registrations"
        }),
        json!({
            "protocol_version": 1,
            "registrations": [],
            "state": "registrations_current"
        }),
        json!({
            "protocol_version": 1,
            "registrations": [],
            "state": "future_state"
        }),
    ] {
        assert!(serde_json::from_value::<Lnv1RegistryEvidenceV1>(invalid).is_err());
    }
}

#[test]
fn expired_evidence_is_distinct_from_absence() {
    assert_eq!(
        Lnv1RegistryEvidenceV1::no_registrations().state(),
        Lnv1RegistryState::NoRegistrations
    );
    assert_eq!(
        Lnv1RegistryEvidenceV1::registrations_expired().state(),
        Lnv1RegistryState::RegistrationsExpired
    );
}
