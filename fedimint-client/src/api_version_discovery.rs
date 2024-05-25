use std::collections::BTreeMap;

use anyhow::format_err;
use fedimint_api_client::api::ApiVersionSet;
use fedimint_core::module::{
    ApiVersion, SupportedApiVersionsSummary, SupportedCoreApiVersions, SupportedModuleApiVersions,
};
use fedimint_core::PeerId;

fn discover_common_core_api_version(
    client_versions: &SupportedCoreApiVersions,
    peer_versions: BTreeMap<PeerId, SupportedCoreApiVersions>,
) -> Option<ApiVersion> {
    let mut best_major = None;
    let mut best_major_peer_num = 0;

    // Find major api version with highest peer number supporting it
    for client_api_version in &client_versions.api {
        let peers_compatible_num = peer_versions
            .values()
            .filter_map(|supported_versions| {
                supported_versions
                    .get_minor_api_version(client_versions.core_consensus, client_api_version.major)
            })
            .filter(|peer_minor| client_api_version.minor <= *peer_minor)
            .count();

        if best_major_peer_num < peers_compatible_num {
            best_major = Some(client_api_version);
            best_major_peer_num = peers_compatible_num;
        }
    }

    // Adjust the minor version to the smallest supported by all matching peers
    best_major.map(
        |ApiVersion {
             major: best_major,
             minor: best_major_minor,
         }| ApiVersion {
            major: best_major,
            minor: peer_versions
                .values()
                .filter_map(|supported| {
                    supported.get_minor_api_version(client_versions.core_consensus, best_major)
                })
                .filter(|peer_minor| best_major_minor <= *peer_minor)
                .min()
                .expect("We must have at least one"),
        },
    )
}

#[test]
fn discover_common_core_api_version_sanity() {
    use fedimint_core::module::MultiApiVersion;

    let core_consensus = fedimint_core::module::CoreConsensusVersion::new(0, 0);
    let client_versions = SupportedCoreApiVersions {
        core_consensus,
        api: MultiApiVersion::try_from_iter([
            ApiVersion { major: 2, minor: 3 },
            ApiVersion { major: 3, minor: 1 },
        ])
        .unwrap(),
    };

    assert!(discover_common_core_api_version(&client_versions, BTreeMap::from([])).is_none());
    assert_eq!(
        discover_common_core_api_version(
            &client_versions,
            BTreeMap::from([(
                PeerId::from(0),
                SupportedCoreApiVersions {
                    core_consensus: fedimint_core::module::CoreConsensusVersion::new(0, 0),
                    api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 3 }])
                        .unwrap(),
                }
            )])
        ),
        Some(ApiVersion { major: 2, minor: 3 })
    );
    assert_eq!(
        discover_common_core_api_version(
            &client_versions,
            BTreeMap::from([(
                PeerId::from(0),
                SupportedCoreApiVersions {
                    core_consensus: fedimint_core::module::CoreConsensusVersion::new(0, 1), /* different minor consensus version, we don't care */
                    api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 3 }])
                        .unwrap(),
                }
            )])
        ),
        Some(ApiVersion { major: 2, minor: 3 })
    );
    assert_eq!(
        discover_common_core_api_version(
            &client_versions,
            BTreeMap::from([(
                PeerId::from(0),
                SupportedCoreApiVersions {
                    core_consensus: fedimint_core::module::CoreConsensusVersion::new(1, 0), /* wrong consensus version */
                    api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 4 }])
                        .unwrap(),
                }
            )])
        ),
        None
    );
    assert_eq!(
        discover_common_core_api_version(
            &client_versions,
            BTreeMap::from([
                (
                    PeerId::from(0),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 2 }])
                            .unwrap(),
                    }
                ),
                (
                    PeerId::from(1),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 1 }])
                            .unwrap(),
                    }
                ),
                (
                    PeerId::from(1),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 3, minor: 1 }])
                            .unwrap(),
                    }
                )
            ])
        ),
        Some(ApiVersion { major: 3, minor: 1 })
    );
    assert_eq!(
        discover_common_core_api_version(
            &client_versions,
            BTreeMap::from([
                (
                    PeerId::from(0),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 4 }])
                            .unwrap(),
                    }
                ),
                (
                    PeerId::from(1),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 5 }])
                            .unwrap(),
                    }
                ),
            ])
        ),
        Some(ApiVersion { major: 2, minor: 4 })
    );
}

fn discover_common_module_api_version(
    client_versions: &SupportedModuleApiVersions,
    peer_versions: BTreeMap<PeerId, SupportedModuleApiVersions>,
) -> Option<ApiVersion> {
    let mut best_major = None;
    let mut best_major_peer_num = 0;

    // Find major api version with highest peer number supporting it
    for client_api_version in &client_versions.api {
        let peers_compatible_num = peer_versions
            .values()
            .filter_map(|supported_versions| {
                supported_versions.get_minor_api_version(
                    client_versions.core_consensus,
                    client_versions.module_consensus,
                    client_api_version.major,
                )
            })
            .filter(|peer_minor| client_api_version.minor <= *peer_minor)
            .count();

        if best_major_peer_num < peers_compatible_num {
            best_major = Some(client_api_version);
            best_major_peer_num = peers_compatible_num;
        }
    }

    // Adjust the minor version to the smallest supported by all matching peers
    best_major.map(
        |ApiVersion {
             major: best_major,
             minor: best_major_minor,
         }| ApiVersion {
            major: best_major,
            minor: peer_versions
                .values()
                .filter_map(|supported| {
                    supported.get_minor_api_version(
                        client_versions.core_consensus,
                        client_versions.module_consensus,
                        best_major,
                    )
                })
                .filter(|peer_minor| best_major_minor <= *peer_minor)
                .min()
                .expect("We must have at least one"),
        },
    )
}

pub fn discover_common_api_versions_set(
    client_versions: &SupportedApiVersionsSummary,
    peer_versions: BTreeMap<PeerId, SupportedApiVersionsSummary>,
) -> anyhow::Result<ApiVersionSet> {
    Ok(ApiVersionSet {
        core: discover_common_core_api_version(
            &client_versions.core,
            peer_versions
                .iter()
                .map(|(peer_id, peer_supported_api_versions)| {
                    (*peer_id, peer_supported_api_versions.core.clone())
                })
                .collect(),
        )
        .ok_or_else(|| format_err!("Could not find a common core API version"))?,
        modules: client_versions
            .modules
            .iter()
            .filter_map(
                |(module_instance_id, client_supported_module_api_versions)| {
                    let discover_common_module_api_version = discover_common_module_api_version(
                        client_supported_module_api_versions,
                        peer_versions
                            .iter()
                            .filter_map(|(peer_id, peer_supported_api_versions_summary)| {
                                peer_supported_api_versions_summary
                                    .modules
                                    .get(module_instance_id)
                                    .map(|versions| (*peer_id, versions.clone()))
                            })
                            .collect(),
                    );
                    discover_common_module_api_version.map(|v| (*module_instance_id, v))
                },
            )
            .collect(),
    })
}
