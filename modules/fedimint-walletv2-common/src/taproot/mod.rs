pub mod frost;

use std::collections::BTreeMap;
use std::sync::Arc;

use bitcoin::ScriptBuf;
use bitcoin::hashes::sha256;
use fedimint_core::{BitcoinHash, NumPeersExt, PeerId};
use miniscript::descriptor::{TapTree, Tr};
use miniscript::{Miniscript, Tap, Terminal, Threshold};
use secp256k1::{PublicKey, Scalar, XOnlyPublicKey};

use crate::config::WalletDescriptor;

/// The federation `script_pubkey` for the UTXO identified by `tweak`,
/// for any descriptor kind: P2WSH for [`WalletDescriptor::Wsh`], P2TR
/// with NUMS internal key + script-path multisig for
/// [`WalletDescriptor::Tr`], P2TR key-path with the lone peer's xonly
/// key for [`WalletDescriptor::SinglePeer`], and P2TR key-path with the
/// FROST aggregate key for [`WalletDescriptor::Frost`]. Shared by the
/// server (deposit addresses, prevout reconstruction) and the client
/// (address derivation).
pub fn script_pubkey_for_descriptor(
    descriptor: &WalletDescriptor,
    bitcoin_pks: &BTreeMap<PeerId, PublicKey>,
    tweak: &sha256::Hash,
) -> ScriptBuf {
    match descriptor {
        WalletDescriptor::Wsh => crate::descriptor(bitcoin_pks, tweak).script_pubkey(),
        WalletDescriptor::Tr => descriptor_tr(bitcoin_pks, tweak, nums_point()).script_pubkey(),
        WalletDescriptor::SinglePeer(peer_xonly) => {
            descriptor_tr_single_peer(*peer_xonly, tweak).script_pubkey()
        }
        WalletDescriptor::Frost(internal_key) => {
            descriptor_tr(bitcoin_pks, tweak, *internal_key).script_pubkey()
        }
    }
}

/// Provably unspendable x-only public key (BIP-341 NUMS point from the
/// BIP-341 spec). Used as the internal key in our Taproot descriptor so
/// that key-path spending is impossible — only the script path may be
/// used.
pub fn nums_point() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&[
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ])
    .expect("Valid x-only public key")
}

/// Apply the per-UTXO fedimint `tweak` to an x-only public key.
///
/// Treats the 32-byte sha256 `tweak` as a scalar and computes
/// `pk + tweak·G`, returning the x-only form of the result. Used to
/// derive the unique pubkey that controls each federation UTXO from a
/// guardian's bitcoin pubkey, so every UTXO has a distinct
/// `script_pubkey` even though the underlying keyset is fixed. The
/// matching private-side tweak is `add_xonly_tweak` on the keypair —
/// see signing call sites in `taproot/{multisig,frost,single_peer}.rs`.
pub fn tweak_xonly_public_key(pk: &XOnlyPublicKey, tweak: &sha256::Hash) -> XOnlyPublicKey {
    let full_pk = PublicKey::from_x_only_public_key(*pk, secp256k1::Parity::Even);
    let tweaked = full_pk
        .add_exp_tweak(
            secp256k1::SECP256K1,
            &Scalar::from_be_bytes(tweak.to_byte_array()).expect("Hash is within field order"),
        )
        .expect("Failed to tweak bitcoin public key");
    tweaked.x_only_public_key().0
}

/// Build the federation's Taproot multi-`a` descriptor for the given tweak.
///
/// The internal key is a provably unspendable BIP-341 NUMS point so the
/// only way to spend is via the script path. The script path commits to a
/// `multi_a` of the guardians' tweaked x-only keys.
pub fn descriptor_tr(
    pks: &BTreeMap<PeerId, PublicKey>,
    tweak: &sha256::Hash,
    internal_key: XOnlyPublicKey,
) -> Tr<XOnlyPublicKey> {
    let threshold = pks.to_num_peers().threshold();
    let mut tweaked: Vec<XOnlyPublicKey> = pks
        .values()
        .map(|pk| tweak_xonly_public_key(&pk.x_only_public_key().0, tweak))
        .collect();
    tweaked.sort();

    let thresh = Threshold::new(threshold, tweaked).expect("Failed to create multi_a threshold");
    let ms = Miniscript::<XOnlyPublicKey, Tap>::from_ast(Terminal::MultiA(thresh))
        .expect("Failed to create multi_a miniscript");
    let tree = TapTree::Leaf(Arc::new(ms));

    let internal_tweaked = tweak_xonly_public_key(&internal_key, tweak);

    Tr::new(internal_tweaked, Some(tree)).expect("Failed to construct Tr descriptor")
}

/// Single-peer Taproot descriptor: just `tr(internal_key)` with no
/// taptree. The internal key is the lone peer's x-only bitcoin pubkey
/// (after applying the per-UTXO `tweak`). Used for `N=1` federations
/// when the leader picked Tr or Frost — both collapse to this since
/// multisig and FROST both degenerate to a single signature.
pub fn descriptor_tr_single_peer(
    internal_key: XOnlyPublicKey,
    tweak: &sha256::Hash,
) -> Tr<XOnlyPublicKey> {
    let internal_tweaked = tweak_xonly_public_key(&internal_key, tweak);
    Tr::new(internal_tweaked, None).expect("Failed to construct single-peer Tr descriptor")
}
