use std::collections::BTreeMap;

use aleph_bft::{Keychain as _, MultiKeychain as _, NodeCount, NodeIndex, NodeMap};
use fedimint_core::encoding::Encodable;
use fedimint_core::{PeerId, secp256k1};
use secp256k1::{Keypair, SecretKey};

use super::Keychain;

fn keychain() -> Keychain {
    let keypair = Keypair::from_secret_key(
        secp256k1::SECP256K1,
        &SecretKey::from_slice(&[1; 32]).expect("Valid secret key"),
    );

    let pks = BTreeMap::from([(PeerId::from(0), keypair.public_key())]);

    Keychain {
        identity: PeerId::from(0),
        message_tag: pks.consensus_hash(),
        pks,
        keypair,
    }
}

#[test]
fn verify_rejects_out_of_range_node_index() {
    let keychain = keychain();
    let signature = keychain.sign(b"message");

    assert!(keychain.verify(b"message", &signature, NodeIndex(0)));

    // A malicious peer can embed an arbitrary u64 index in a unit it sends us and
    // aleph-bft verifies the signature before it validates that index, so this must
    // return false rather than panic and take the consensus session down.
    assert!(!keychain.verify(b"message", &signature, NodeIndex(usize::from(u16::MAX) + 1)));
    assert!(!keychain.verify(b"message", &signature, NodeIndex(usize::MAX)));
}

#[test]
fn incomplete_rejects_empty_public_key_set() {
    let mut keychain = keychain();
    keychain.pks.clear();

    assert!(!keychain.is_complete(b"message", &NodeMap::with_size(NodeCount(0))));
}
