use fedimint_api_client::api::{FederationError, ServerError};
use fedimint_core::PeerId;
use fedimint_meta_common::MetaValue;
use serde_json::json;

use super::{
    MetaConsensusValue, MetaModuleSource, format_rpc_consensus_value_response, meta_module_source,
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
