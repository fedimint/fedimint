use serde_json::json;

use super::Lnv2RegistryEvidenceV1;

#[test]
fn wire_has_no_ttl_or_expiry_semantics() {
    let value =
        serde_json::to_value(Lnv2RegistryEvidenceV1::new(vec![])).expect("serialization must work");
    assert_eq!(
        value,
        json!({
            "protocol_version": 1,
            "registrations": [],
            "state": "no_registrations"
        })
    );
    let object = value.as_object().expect("response must be an object");
    assert!(object.keys().all(|key| !key.contains("ttl")));
    assert!(object.keys().all(|key| !key.contains("expir")));
    let mut additive = value;
    additive
        .as_object_mut()
        .expect("snapshot is an object")
        .insert("future_optional_field".to_owned(), json!(true));
    assert!(serde_json::from_value::<Lnv2RegistryEvidenceV1>(additive).is_ok());
}

#[test]
fn malformed_unknown_and_expired_states_fail_closed() {
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
            "state": "registrations_expired"
        }),
    ] {
        assert!(serde_json::from_value::<Lnv2RegistryEvidenceV1>(invalid).is_err());
    }
}
