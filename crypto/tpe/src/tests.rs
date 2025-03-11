use bitcoin_hashes::{Hash, sha256};
use bls12_381::{G1Projective, Scalar};
use group::Curve;
use group::ff::Field;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use crate::{
    AggregatePublicKey, PublicKeyShare, SecretKeyShare, aggregate_dk_shares, create_dk_share,
    decrypt_preimage, derive_agg_dk, derive_pk_share, encrypt_preimage, verify_agg_dk,
    verify_ciphertext, verify_dk_share,
};

fn dealer_agg_pk() -> AggregatePublicKey {
    AggregatePublicKey((G1Projective::generator() * coefficient(0)).to_affine())
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

    let encryption_seed = [7_u8; 32];
    let preimage = [42_u8; 32];
    let commitment = sha256::Hash::hash(&[0_u8; 32]);
    let ct = encrypt_preimage(&dealer_agg_pk(), &encryption_seed, &preimage, &commitment);

    assert!(verify_ciphertext(&ct, &commitment));

    for peer in 0..PEERS {
        assert!(verify_dk_share(
            &dealer_pk(THRESHOLD, peer),
            &create_dk_share(&dealer_sk(THRESHOLD, peer), &ct),
            &ct,
            &commitment
        ));
    }

    let selected_shares = (0..THRESHOLD)
        .map(|peer| (peer, create_dk_share(&dealer_sk(THRESHOLD, peer), &ct)))
        .collect();

    let agg_dk = aggregate_dk_shares(&selected_shares);

    assert_eq!(agg_dk, derive_agg_dk(&dealer_agg_pk(), &encryption_seed));

    assert!(verify_agg_dk(&dealer_agg_pk(), &agg_dk, &ct, &commitment));

    assert_eq!(preimage, decrypt_preimage(&ct, &agg_dk));
}
