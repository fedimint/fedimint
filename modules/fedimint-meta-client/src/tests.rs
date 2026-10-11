use fedimint_client_module::meta::MetaFieldKey;
use fedimint_core::config::META_FEDERATION_NAME_KEY;
use fedimint_meta_common::MetaValue;
use serde_json::json;

use super::{MetaConsensusValue, format_rpc_consensus_value_response, parse_meta_values};

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
