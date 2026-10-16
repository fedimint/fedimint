use super::{DkgVersion, release_version};
use crate::encoding::{Decodable, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

#[test]
fn release_version_ignores_pre_release_and_build_metadata() {
    assert_eq!(release_version("1.2.3-alpha.1"), "1.2.3");
    assert_eq!(release_version("1.2.3-beta"), "1.2.3");
    assert_eq!(release_version("1.2.3-rc.1"), "1.2.3");
    assert_eq!(release_version("1.2.3+vendor-a"), "1.2.3");
    assert_eq!(release_version("1.2.3-alpha.1+vendor-a"), "1.2.3");
}

#[test]
fn dkg_version_ignores_patch_and_pre_release_but_preserves_vendor() {
    let version = DkgVersion::parse("1.2.3-alpha.1+vendor-a").expect("valid version");

    assert_eq!(version.setup_code_version().to_string(), "1.2.3+vendor-a");
    assert_eq!(version.compatibility_version().to_string(), "1.2+vendor-a");

    let patch_skew = DkgVersion::parse("1.2.4-beta+vendor-a").expect("valid version");
    assert_eq!(
        version.compatibility_version(),
        patch_skew.compatibility_version()
    );
}

#[test]
fn dkg_version_distinguishes_vendor_identity() {
    let upstream = DkgVersion::parse("1.2.3").expect("valid version");
    let vendor_a = DkgVersion::parse("1.2.3+vendor-a").expect("valid version");
    let vendor_b = DkgVersion::parse("1.2.3+vendor-b").expect("valid version");

    assert_ne!(
        upstream.compatibility_version(),
        vendor_a.compatibility_version()
    );
    assert_ne!(
        vendor_a.compatibility_version(),
        vendor_b.compatibility_version()
    );
}

#[test]
fn dkg_version_rejects_malformed_versions() {
    for version in ["", "1", "1.2", "1.2.3.4", "1.02.3", "1.2.x", "v1.2.3"] {
        assert!(
            DkgVersion::parse(version).is_err(),
            "{version:?} should be rejected"
        );
    }
}

#[test]
fn dkg_version_preserves_historical_string_encodings() {
    let version = DkgVersion::parse("1.2.3-alpha.1+vendor-a").expect("valid version");
    let encoded = version.consensus_encode_to_vec();

    assert_eq!(
        encoded,
        "1.2.3+vendor-a".to_owned().consensus_encode_to_vec()
    );
    assert_eq!(
        DkgVersion::consensus_decode_whole(&encoded, &ModuleDecoderRegistry::default())
            .expect("valid encoded version"),
        version
    );
    assert_eq!(
        serde_json::to_string(&version).expect("version serializes"),
        "\"1.2.3+vendor-a\""
    );
}

#[test]
fn dkg_version_rejects_malformed_string_encoding() {
    let encoded = "fedimint-code-version".to_owned().consensus_encode_to_vec();

    assert!(
        DkgVersion::consensus_decode_whole(&encoded, &ModuleDecoderRegistry::default()).is_err()
    );
}
