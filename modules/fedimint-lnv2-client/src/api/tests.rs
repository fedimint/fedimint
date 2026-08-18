use fedimint_lnv2_common::gateway_registry::{
    LNV2_REGISTRY_SNAPSHOT_VERSION, Lnv2RegistrySnapshotResult, Lnv2RegistrySnapshotV1,
};
use serde_json::json;

use super::parse_lnv2_registry_responses;

#[test]
fn guardian_registry_responses_are_merged_and_invalid_sets_are_rejected() {
    let url = fedimint_core::util::SafeUrl::parse("https://gateway.example/").expect("valid URL");
    let current =
        serde_json::to_value(Lnv2RegistrySnapshotV1::new(vec![url.clone()])).expect("serializes");
    let result = parse_lnv2_registry_responses(vec![current.clone(), current.clone()])
        .expect("matching guardian responses");
    let Lnv2RegistrySnapshotResult::Snapshot(snapshot) = result else {
        panic!("current snapshot version must be supported");
    };
    assert_eq!(snapshot.registrations(), &[url]);

    assert!(
        parse_lnv2_registry_responses(vec![json!({
            "protocol_version": LNV2_REGISTRY_SNAPSHOT_VERSION,
            "registrations": [],
            "state": "registrations_current"
        })])
        .is_err()
    );
    assert_eq!(
        parse_lnv2_registry_responses(vec![json!({
            "protocol_version": LNV2_REGISTRY_SNAPSHOT_VERSION + 1,
            "future": "shape"
        })])
        .expect("future version is classified"),
        Lnv2RegistrySnapshotResult::UnsupportedVersion {
            protocol_version: LNV2_REGISTRY_SNAPSHOT_VERSION + 1
        }
    );
}
