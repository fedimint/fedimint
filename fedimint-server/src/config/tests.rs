use std::collections::{BTreeMap, BTreeSet};

use fedimint_core::{PeerId, secp256k1};
use rand::rngs::OsRng;

use super::{ConfigGenParams, ServerConfig};

fn server_config_with_code_version(code_version: &str) -> ServerConfig {
    let (broadcast_secret_key, _) = secp256k1::generate_keypair(&mut OsRng);

    ServerConfig::from(
        ConfigGenParams {
            identity: PeerId::from(0),
            tls_key: None,
            iroh_api_sk: None,
            iroh_p2p_sk: None,
            peers: BTreeMap::new(),
            meta: BTreeMap::new(),
            disable_base_fees: false,
            enabled_modules: BTreeSet::new(),
            network: bitcoin::Network::Regtest,
        },
        PeerId::from(0),
        BTreeMap::new(),
        broadcast_secret_key,
        BTreeMap::new(),
        code_version.to_owned(),
    )
}

#[test]
fn server_config_uses_dkg_compatibility_identity_as_consensus_code_version() {
    let patch_3 = server_config_with_code_version("1.2.3-alpha+fedi");
    let patch_4 = server_config_with_code_version("1.2.4+fedi");
    let upstream = server_config_with_code_version("1.2.4");
    let other_vendor = server_config_with_code_version("1.2.4+acme");
    let next_minor = server_config_with_code_version("1.3.0");

    assert_eq!(patch_3.consensus.code_version, "1.2+fedi");
    assert_eq!(
        patch_3.consensus.code_version,
        patch_4.consensus.code_version
    );
    assert_ne!(
        patch_3.consensus.code_version,
        upstream.consensus.code_version
    );
    assert_ne!(
        patch_3.consensus.code_version,
        other_vendor.consensus.code_version
    );
    assert_ne!(
        patch_3.consensus.code_version,
        next_minor.consensus.code_version
    );
}

#[test]
fn server_config_accepts_opaque_test_code_versions() {
    let config = server_config_with_code_version("fedimint-code-version");

    assert_eq!(config.consensus.code_version, "fedimint");
}
