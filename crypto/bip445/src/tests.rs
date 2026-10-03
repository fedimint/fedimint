use std::collections::BTreeMap;
use std::iter::once;

use bitcoin::hashes::{Hash as BitcoinHash, sha256};
use rand::SeedableRng;
use rand::rngs::OsRng;
use rand_chacha::ChaChaRng;
use secp256k1::{SECP256K1, Scalar, SecretKey, constants};

use crate::{
    AggregatePublicKey, PublicKeyShare, SecretKeyShare, SignatureShare, aggregate_signature_shares,
    derive_pk_share, generate_nonce, invert, key_from_u64, key_scalar, scalar_from_u64,
    scalar_mod_order, sign_share, verify, verify_signature_share,
};

fn dealer_agg_pk() -> AggregatePublicKey {
    AggregatePublicKey(coefficient(0).public_key(SECP256K1))
}

fn dealer_pk(threshold: u64, peer: u64) -> PublicKeyShare {
    derive_pk_share(&dealer_sk(threshold, peer))
}

fn dealer_sk(threshold: u64, peer: u64) -> SecretKeyShare {
    let x = scalar_from_u64(peer + 1);

    // We evaluate the secret polynomial of degree threshold - 1 at the point x
    // using the Horner schema.

    let y = (0..threshold)
        .map(coefficient)
        .rev()
        .reduce(|accumulator, c| {
            accumulator
                .mul_tweak(&x)
                .expect("The evaluation point is nonzero")
                .add_tweak(&key_scalar(&c))
                .expect("The intermediate values are nonzero for this dealer polynomial")
        })
        .expect("We have at least one coefficient");

    SecretKeyShare(y)
}

fn coefficient(index: u64) -> SecretKey {
    SecretKey::new(&mut ChaChaRng::from_seed(
        *sha256::Hash::hash(&index.to_be_bytes()).as_byte_array(),
    ))
}

#[test]
fn test_roundtrip() {
    const THRESHOLD: u64 = 3;

    let message = [7_u8; 32];

    let mut secret_nonces = BTreeMap::new();
    let mut public_nonces = BTreeMap::new();

    for peer in 0..THRESHOLD {
        let (secret_nonce, public_nonce) = generate_nonce();

        secret_nonces.insert(peer, secret_nonce);
        public_nonces.insert(peer, public_nonce);
    }

    let shares = secret_nonces
        .into_iter()
        .map(|(peer, nonce)| {
            let share = sign_share(
                message,
                &dealer_sk(THRESHOLD, peer),
                nonce,
                &public_nonces,
                peer,
                &dealer_agg_pk(),
            );

            (peer, share)
        })
        .collect::<BTreeMap<u64, SignatureShare>>();

    for (peer, share) in &shares {
        assert!(verify_signature_share(
            message,
            *peer,
            &dealer_pk(THRESHOLD, *peer),
            share,
            &public_nonces,
            &dealer_agg_pk()
        ));
    }

    let signature = aggregate_signature_shares(message, &public_nonces, &shares, &dealer_agg_pk());

    assert!(verify(message, &signature, &dealer_agg_pk()));
}

#[test]
fn test_one_of_one() {
    let message = [11_u8; 32];

    let (secret_nonce, public_nonce) = generate_nonce();

    let nonces = once((0, public_nonce)).collect::<BTreeMap<u64, _>>();

    let share = sign_share(
        message,
        &dealer_sk(1, 0),
        secret_nonce,
        &nonces,
        0,
        &dealer_agg_pk(),
    );

    assert!(verify_signature_share(
        message,
        0,
        &dealer_pk(1, 0),
        &share,
        &nonces,
        &dealer_agg_pk()
    ));

    let signature = aggregate_signature_shares(
        message,
        &nonces,
        &once((0, share)).collect(),
        &dealer_agg_pk(),
    );

    assert!(verify(message, &signature, &dealer_agg_pk()));
}

#[test]
fn test_invert() {
    let key = SecretKey::new(&mut OsRng);

    let product = invert(&key)
        .mul_tweak(&key_scalar(&key))
        .expect("The product of a scalar and its inverse is one");

    assert_eq!(product, key_from_u64(1));
}

#[test]
fn test_scalar_mod_order() {
    assert_eq!(scalar_mod_order(constants::CURVE_ORDER), Scalar::ZERO);

    let mut bytes = constants::CURVE_ORDER;

    bytes[31] += 1;

    assert_eq!(scalar_mod_order(bytes), Scalar::ONE);
}
