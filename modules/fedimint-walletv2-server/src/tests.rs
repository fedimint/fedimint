use bitcoin::hashes::{Hash, sha256};
use fedimint_core::PeerId;
use fedimint_walletv2_common::config::WalletDescriptor;
use secp256k1::{Parity, Scalar, SecretKey};

use crate::taproot::frost::trusted_setup;
use crate::{recovery_public_key, recovery_secret_key};

/// Secret keys covering both parities of their public key's Y coordinate.
fn secret_keys() -> Vec<SecretKey> {
    let keys: Vec<SecretKey> = (1..=8u8)
        .map(|byte| SecretKey::from_slice(&[byte; 32]).expect("Valid secret key"))
        .collect();

    let parities: Vec<Parity> = keys
        .iter()
        .map(|sk| sk.x_only_public_key(secp256k1::SECP256K1).1)
        .collect();

    assert!(parities.contains(&Parity::Even), "Need an even-Y key");
    assert!(parities.contains(&Parity::Odd), "Need an odd-Y key");

    keys
}

fn descriptors() -> Vec<WalletDescriptor> {
    let peers: Vec<PeerId> = (0..4).map(PeerId::from).collect();
    let (polynomial, _) = trusted_setup(&peers);

    vec![
        WalletDescriptor::Wsh,
        WalletDescriptor::Tr,
        WalletDescriptor::SinglePeer(secret_keys()[0].x_only_public_key(secp256k1::SECP256K1).0),
        WalletDescriptor::Frost(polynomial),
    ]
}

#[test]
fn recovery_secret_key_matches_recovery_public_key() {
    let tweak = sha256::Hash::hash(b"federation utxo tweak");

    for descriptor in descriptors() {
        for sk in secret_keys() {
            let derived_pk =
                recovery_secret_key(&descriptor, &sk, &tweak).public_key(secp256k1::SECP256K1);

            let derived_pk = match descriptor {
                WalletDescriptor::Wsh => derived_pk.to_string(),
                WalletDescriptor::Tr
                | WalletDescriptor::SinglePeer(_)
                | WalletDescriptor::Frost(_) => derived_pk.x_only_public_key().0.to_string(),
            };

            assert_eq!(
                derived_pk,
                recovery_public_key(&descriptor, &sk.public_key(secp256k1::SECP256K1), &tweak),
                "Recovery keys disagree for {descriptor:?} with a {:?}-Y key",
                sk.x_only_public_key(secp256k1::SECP256K1).1,
            );
        }
    }
}

#[test]
fn wsh_recovery_secret_key_adds_the_tweak() {
    let tweak = sha256::Hash::hash(b"federation utxo tweak");
    let scalar = Scalar::from_be_bytes(tweak.to_byte_array()).expect("Hash is within field order");

    for sk in secret_keys() {
        assert_eq!(
            recovery_secret_key(&WalletDescriptor::Wsh, &sk, &tweak),
            sk.add_tweak(&scalar).expect("Tweak succeeds"),
        );
    }
}
