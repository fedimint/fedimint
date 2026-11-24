use fedimint_api_client::api::{FederationError, ServerError};
use fedimint_client_module::meta::MetaFieldKey;
use fedimint_core::PeerId;
use fedimint_core::config::META_FEDERATION_NAME_KEY;
use fedimint_meta_common::MetaValue;
use serde_json::json;

use super::{
    MetaConsensusValue, MetaModuleSource, format_rpc_consensus_value_response, meta_module_source,
    parse_meta_values,
};

fn unreachable() -> FederationError {
    let peer_id = PeerId::from(3);
    FederationError::new_one_peer(
        peer_id,
        "get_consensus",
        (),
        ServerError::InvalidPeerId { peer_id },
    )
}

fn consensus(revision: u64) -> MetaConsensusValue {
    MetaConsensusValue {
        revision,
        value: MetaValue::from(br#"{"federation_name":"Current name"}"#.as_slice()),
    }
}

#[test]
fn unreachable_meta_module_keeps_stored_values() {
    assert!(matches!(
        meta_module_source(Some(Err(unreachable())), Some(1)),
        MetaModuleSource::KeepStored(_)
    ));
    // Revision 0 is a stored value too, not "nothing stored".
    assert!(matches!(
        meta_module_source(Some(Err(unreachable())), Some(0)),
        MetaModuleSource::KeepStored(_)
    ));
}

#[test]
fn unreachable_meta_module_without_stored_values_uses_legacy() {
    assert!(matches!(
        meta_module_source(Some(Err(unreachable())), None),
        MetaModuleSource::Legacy
    ));
}

#[test]
fn absent_meta_value_uses_legacy_even_with_stored_values() {
    assert!(matches!(
        meta_module_source(Some(Ok(None)), Some(1)),
        MetaModuleSource::Legacy
    ));
    assert!(matches!(
        meta_module_source(None, Some(1)),
        MetaModuleSource::Legacy
    ));
}

#[test]
fn consensus_value_replaces_stored_values() {
    match meta_module_source(Some(Ok(Some(consensus(4)))), Some(9)) {
        MetaModuleSource::Consensus(value) => assert_eq!(value, consensus(4)),
        other => panic!("expected the consensus value, got {other:?}"),
    }
}

#[test]
fn module_federation_names_are_literal_strings() {
    for name in ["Example", "123", "true", "null", "\"Quoted name\"", "{}"] {
        let values = parse_meta_values(
            &serde_json::to_vec(&json!({
                "federation_name": name,
                "legacy_nested": "{\"enabled\":true}",
            }))
            .expect("test JSON should serialize"),
        )
        .expect("test metadata should parse");
        assert_eq!(
            values[&MetaFieldKey(META_FEDERATION_NAME_KEY.to_owned())].0,
            json!(name)
        );
        assert_eq!(
            values[&MetaFieldKey("legacy_nested".to_owned())].0,
            json!({"enabled": true}),
            "other fields retain legacy JSON-string compatibility"
        );
    }
}

#[test]
fn formats_consensus_value_as_json() {
    let response = format_rpc_consensus_value_response(Some(MetaConsensusValue {
        revision: 7,
        value: MetaValue::from(br#"{"welcome_message":"hello"}"#.as_slice()),
    }))
    .expect("valid json meta value should format");

    assert_eq!(
        response,
        json!({
            "revision": 7,
            "value": {
                "welcome_message": "hello",
            },
        })
    );
}

#[test]
fn formats_missing_consensus_value_as_null() {
    let response = format_rpc_consensus_value_response(None).expect("null response should format");

    assert_eq!(response, serde_json::Value::Null);
}
