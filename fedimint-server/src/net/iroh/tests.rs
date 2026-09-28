use fedimint_core::secp256k1::SecretKey;

use super::derive_iroh_v1_api_secret_key;

#[test]
fn iroh_v1_api_key_derivation_is_stable() {
    let broadcast_sk = SecretKey::from_slice(&[1; 32]).expect("valid test key");
    assert_eq!(
        derive_iroh_v1_api_secret_key(&broadcast_sk)
            .public()
            .to_string(),
        "e4b678498c23a7444ac2daf4aed336e88c2fa51c10e973f4ec57ae493e25fcf3"
    );
}
