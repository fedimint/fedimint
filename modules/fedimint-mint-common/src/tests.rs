use fedimint_core::secp256k1::{PublicKey, SECP256K1, SecretKey};

use super::Nonce;

/// The secp256k1 generator point, whose compressed encoding is well known.
fn generator_nonce() -> Nonce {
    let mut one = [0; 32];
    one[31] = 1;
    let one = SecretKey::from_slice(&one).expect("valid secret key");
    Nonce(PublicKey::from_secret_key(SECP256K1, &one))
}

const GENERATOR_HEX: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

#[test]
fn nonce_full_fmt_respects_precision() {
    let nonce = generator_nonce();

    assert_eq!(nonce.fmt_full().to_string(), GENERATOR_HEX);
    assert_eq!(format!("{:.0}", nonce.fmt_full()), "");
    assert_eq!(format!("{:.5}", nonce.fmt_full()), "0279b");
    assert_eq!(format!("{:.65}", nonce.fmt_full()), &GENERATOR_HEX[..65]);
}

#[test]
fn nonce_short_fmt_respects_precision() {
    let nonce = generator_nonce();

    assert_eq!(nonce.fmt_short().to_string(), "0279be66_16f81798");
    assert_eq!(format!("{:.0}", nonce.fmt_short()), "_");
    assert_eq!(format!("{:.3}", nonce.fmt_short()), "027_16f");
    assert_eq!(format!("{:.5}", nonce.fmt_short()), "0279b_16f81");
    assert_eq!(format!("{:.7}", nonce.fmt_short()), "0279be6_16f8179");
}
