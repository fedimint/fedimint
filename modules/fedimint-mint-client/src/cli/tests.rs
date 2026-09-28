use bls12_381::G1Affine;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use tbs::BlindedMessage;

use super::{BlindNonce, Nonce};

/// The hex `dev check-nonce` accepts is the plain compressed public key, so
/// it matches what the JSON representation of a nonce shows.
#[test]
fn nonce_hex_round_trip() {
    let nonce_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let nonce = Nonce::consensus_decode_hex(nonce_hex, &ModuleDecoderRegistry::default())
        .expect("Valid compressed public key");

    assert_eq!(nonce.consensus_encode_to_hex(), nonce_hex);
}

/// Same for `dev check-blind-nonce` and the compressed G1 point.
#[test]
fn blind_nonce_hex_round_trip() {
    let blind_nonce = BlindNonce(BlindedMessage(G1Affine::generator()));
    let blind_nonce_hex = blind_nonce.consensus_encode_to_hex();

    assert_eq!(blind_nonce_hex.len(), 96);
    assert_eq!(
        BlindNonce::consensus_decode_hex(&blind_nonce_hex, &ModuleDecoderRegistry::default())
            .expect("Valid compressed G1 point"),
        blind_nonce
    );
}
