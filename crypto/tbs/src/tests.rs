use std::collections::BTreeMap;

use bls12_381::{G2Projective, Scalar};
use fedimint_core::BitcoinHash;
use fedimint_core::bitcoin::hashes::sha256;
use group::Curve;
use group::ff::Field;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use crate::{
    AggregatePublicKey, BlindedSignatureShare, BlindingKey, Message, PublicKeyShare,
    SecretKeyShare, aggregate_signature_shares, blind_message, derive_pk_share, sign_message,
    unblind_signature, verify, verify_signature_share,
};

fn dealer_agg_pk() -> AggregatePublicKey {
    AggregatePublicKey((G2Projective::generator() * coefficient(0)).to_affine())
}

fn dealer_pk(threshold: u64, peer: u64) -> PublicKeyShare {
    derive_pk_share(&dealer_sk(threshold, peer))
}

fn dealer_sk(threshold: u64, peer: u64) -> SecretKeyShare {
    let x = Scalar::from(peer + 1);

    // We evaluate the scalar polynomial of degree threshold - 1 at the point x
    // using the Horner schema.

    let y = (0..threshold)
        .map(coefficient)
        .rev()
        .reduce(|accumulator, c| accumulator * x + c)
        .expect("We have at least one coefficient");

    SecretKeyShare(y)
}

fn coefficient(index: u64) -> Scalar {
    Scalar::random(&mut ChaChaRng::from_seed(
        *sha256::Hash::hash(&index.to_be_bytes()).as_byte_array(),
    ))
}

#[test]
fn test_roundtrip() {
    const PEERS: u64 = 4;
    const THRESHOLD: u64 = 3;

    let message = Message::from_bytes(b"Hello World!");
    let blinding_key = BlindingKey::random();

    let b_message = blind_message(message, blinding_key);

    for peer in 0..PEERS {
        assert!(verify_signature_share(
            b_message,
            sign_message(b_message, dealer_sk(THRESHOLD, peer)),
            dealer_pk(THRESHOLD, peer)
        ));
    }

    let signature_shares = (0..THRESHOLD)
        .map(|peer| (peer, sign_message(b_message, dealer_sk(THRESHOLD, peer))))
        .collect::<BTreeMap<u64, BlindedSignatureShare>>();

    let signature = aggregate_signature_shares(&signature_shares);

    let signature = unblind_signature(blinding_key, signature);

    assert!(verify(message, signature, dealer_agg_pk()));
}

#[test]
fn test_blindingkey_fingerprint_multiple_calls_same_result() {
    let bkey = BlindingKey::random();
    assert_eq!(bkey.fingerprint(), bkey.fingerprint());
}

#[test]
fn test_blindingkey_fingerprint_ne_scalar() {
    let bkey = BlindingKey::random();
    assert_ne!(bkey.fingerprint(), bkey.0.to_bytes());
}
