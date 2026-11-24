use std::collections::BTreeMap;

use bitcoin::hashes::{Hash, sha256};
use fedimint_core::{NumPeersExt, PeerId};
use miniscript::descriptor::Wsh;
use secp256k1::{PublicKey, Scalar, SecretKey};

use super::{descriptor, tweak_public_key};

#[test]
fn pending_outputs_preserves_legacy_numeric_wire_format() {
    use serde_json::json;

    use super::{MempoolVisibility, PendingOutput, PendingOutputs};

    // This mirrors the old API model, independently of the new field adapter.
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct LegacyPendingOutputs {
        block_count: u64,
        outputs: Vec<PendingOutput>,
        mempool_visibility: MempoolVisibility,
    }

    for count in [0, 1, 105, u64::MAX] {
        let legacy = LegacyPendingOutputs {
            block_count: count,
            outputs: vec![],
            mempool_visibility: MempoolVisibility::Unavailable,
        };
        let wire = serde_json::to_value(&legacy).expect("Legacy response serializes");
        let pending: PendingOutputs =
            serde_json::from_value(wire.clone()).expect("New clients read legacy responses");
        assert_eq!(pending.block_count, (count != 0).then_some(count));
        let encoded = serde_json::to_value(&pending).expect("New response serializes");
        assert_eq!(encoded, wire);
        assert_eq!(
            serde_json::from_value::<LegacyPendingOutputs>(encoded)
                .expect("Legacy clients read new responses"),
            legacy
        );
    }

    let default_wire =
        serde_json::to_value(PendingOutputs::default()).expect("Default response serializes");
    assert_eq!(default_wire["block_count"], json!(0));
    let zero_count = PendingOutputs {
        block_count: Some(0),
        ..PendingOutputs::default()
    };
    let zero_wire = serde_json::to_value(zero_count).expect("A zero count serializes");
    assert_eq!(zero_wire, default_wire);
    assert_eq!(
        serde_json::from_value::<PendingOutputs>(zero_wire)
            .expect("The wire sentinel decodes as unavailable"),
        PendingOutputs::default()
    );
    // The compatibility boundary remains a required u64, not a nullable field.
    for invalid in [json!(null), json!(-1), json!("105")] {
        let mut wire = default_wire.clone();
        wire["block_count"] = invalid;
        assert!(serde_json::from_value::<PendingOutputs>(wire).is_err());
    }
    let mut missing = default_wire;
    missing
        .as_object_mut()
        .expect("Response is an object")
        .remove("block_count");
    assert!(serde_json::from_value::<PendingOutputs>(missing).is_err());
}

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
