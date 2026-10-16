use fedimint_meta_common::MetaValue;
use serde_json::json;

use super::{MetaConsensusValue, format_rpc_consensus_value_response};

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
