use std::collections::BTreeMap;

use bitcoin::hashes::{Hash, sha256};
use fedimint_core::{NumPeersExt, PeerId};
use miniscript::descriptor::Wsh;
use secp256k1::{PublicKey, Scalar, SecretKey};

use super::{descriptor, tweak_public_key};

fn guardian_keys(count: u8) -> BTreeMap<PeerId, PublicKey> {
    (1..=count)
        .map(|index| {
            (
                PeerId::from(u16::from(index)),
                PublicKey::from_secret_key(
                    secp256k1::SECP256K1,
                    &SecretKey::from_slice(&[index; 32]).expect("Valid test key"),
                ),
            )
        })
        .collect()
}

/// The original per-guardian tweak path is an independent reference for the
/// shared-point optimization, including sorting and the federation threshold.
fn reference_descriptor(pks: &BTreeMap<PeerId, PublicKey>, tweak: &sha256::Hash) -> Wsh<PublicKey> {
    Wsh::new_sortedmulti(
        pks.to_num_peers().threshold(),
        pks.values().map(|pk| tweak_public_key(pk, tweak)).collect(),
    )
    .expect("Valid test descriptor")
}

#[test]
fn shared_tweak_preserves_descriptors() {
    let tweaks = [
        Scalar::ZERO.to_be_bytes(),
        Scalar::ONE.to_be_bytes(),
        Scalar::MAX.to_be_bytes(),
    ]
    .into_iter()
    .map(sha256::Hash::from_byte_array)
    .chain((0..128u64).map(|index| sha256::Hash::hash(&index.to_be_bytes())))
    .collect::<Vec<_>>();

    for count in [1, 2, 4, 7, 16] {
        let pks = guardian_keys(count);

        for tweak in &tweaks {
            let actual = descriptor(&pks, tweak);
            let expected = reference_descriptor(&pks, tweak);

            assert_eq!(actual, expected, "count={count}, tweak={tweak}");
            assert_eq!(actual.script_pubkey(), expected.script_pubkey());
        }
    }
}

#[test]
fn shared_tweak_rejects_out_of_range_scalars() {
    let pks = guardian_keys(4);
    let mut curve_order = Scalar::MAX.to_be_bytes();
    *curve_order.last_mut().expect("Scalar has bytes") += 1;

    for bytes in [curve_order, [0xff; 32]] {
        let tweak = sha256::Hash::from_byte_array(bytes);

        assert!(std::panic::catch_unwind(|| descriptor(&pks, &tweak)).is_err());
        assert!(std::panic::catch_unwind(|| reference_descriptor(&pks, &tweak)).is_err());
    }
}

#[test]
fn shared_tweak_rejects_point_at_infinity() {
    // P = -G and t = 1 must fail, not silently omit the cancelling guardian.
    let pks = BTreeMap::from([(
        PeerId::from(0),
        PublicKey::from_secret_key(
            secp256k1::SECP256K1,
            &SecretKey::from_slice(&Scalar::MAX.to_be_bytes()).expect("Valid test key"),
        ),
    )]);
    let tweak = sha256::Hash::from_byte_array(Scalar::ONE.to_be_bytes());

    assert!(std::panic::catch_unwind(|| descriptor(&pks, &tweak)).is_err());
    assert!(std::panic::catch_unwind(|| reference_descriptor(&pks, &tweak)).is_err());
}
