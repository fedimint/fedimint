use bitcoin::hashes::Hash as _;

use super::PreimageAuth;

#[test]
fn accepts_matching_preimage_auth() {
    let preimage_auth = bitcoin::hashes::sha256::Hash::hash(b"preimage auth");

    assert!(PreimageAuth::new(preimage_auth).verifies(preimage_auth));
}

#[test]
fn rejects_non_matching_preimage_auth() {
    let expected = bitcoin::hashes::sha256::Hash::hash(b"expected preimage auth");
    let supplied = bitcoin::hashes::sha256::Hash::hash(b"supplied preimage auth");

    assert!(!PreimageAuth::new(expected).verifies(supplied));
}
