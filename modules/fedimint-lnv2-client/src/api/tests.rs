use fedimint_lnv2_common::gateway_registry::{
    LNV2_REGISTRY_EVIDENCE_PROTOCOL_VERSION, Lnv2RegistryEvidenceCompatibility,
    Lnv2RegistryEvidenceV1,
};
use serde_json::json;

use super::parse_lnv2_registry_responses;

#[test]
fn response_reduction_unions_deduplicates_and_fails_closed() {
    let url = fedimint_core::util::SafeUrl::parse("https://gateway.example/").expect("valid URL");
    let current =
        serde_json::to_value(Lnv2RegistryEvidenceV1::new(vec![url.clone()])).expect("serializes");
    let result = parse_lnv2_registry_responses(vec![current.clone(), current.clone()])
        .expect("coherent peers");
    let Lnv2RegistryEvidenceCompatibility::Compatible(snapshot) = result else {
        panic!("current response must be compatible");
    };
    assert_eq!(snapshot.registrations(), &[url]);

    assert!(
        parse_lnv2_registry_responses(vec![json!({
            "protocol_version": LNV2_REGISTRY_EVIDENCE_PROTOCOL_VERSION,
            "registrations": [],
            "state": "registrations_current"
        })])
        .is_err()
    );
    assert_eq!(
        parse_lnv2_registry_responses(vec![json!({
            "protocol_version": LNV2_REGISTRY_EVIDENCE_PROTOCOL_VERSION + 1,
            "future": "shape"
        })])
        .expect("future version is classified"),
        Lnv2RegistryEvidenceCompatibility::Incompatible {
            protocol_version: LNV2_REGISTRY_EVIDENCE_PROTOCOL_VERSION + 1
        }
    );
}
