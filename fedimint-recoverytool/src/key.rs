use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::hash::Hasher;

use fedimint_core::bitcoin_migration::bitcoin32_to_bitcoin30_secp256k1_secret_key;
use fedimint_wallet_server::common::keys::CompressedPublicKey;
use miniscript::MiniscriptKey;

/// `MiniscriptKey` that is either a WIF-encoded private key or a compressed,
/// hex-encoded public key
#[derive(Debug, Clone, Copy, Eq)]
pub enum Key {
    Public(CompressedPublicKey),
    Private(bitcoin::key::PrivateKey),
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            self.to_compressed_public_key()
                .cmp(&other.to_compressed_public_key()),
        )
    }
}

impl Ord for Key {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_compressed_public_key()
            .cmp(&other.to_compressed_public_key())
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.to_compressed_public_key()
            .eq(&other.to_compressed_public_key())
    }
}

impl std::hash::Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_compressed_public_key().hash(state);
    }
}

impl Key {
    fn to_compressed_public_key(self) -> CompressedPublicKey {
        match self {
            Key::Public(pk) => pk,
            Key::Private(sk) => {
                CompressedPublicKey::new(secp256k1::PublicKey::from_secret_key_global(
                    &bitcoin32_to_bitcoin30_secp256k1_secret_key(&sk.inner),
                ))
            }
        }
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Public(pk) => Display::fmt(pk, f),
            Key::Private(sk) => Display::fmt(sk, f),
        }
    }
}

impl MiniscriptKey for Key {
    fn is_uncompressed(&self) -> bool {
        false
    }

    fn num_der_paths(&self) -> usize {
        0
    }

    type Sha256 = bitcoin::hashes::sha256::Hash;
    type Hash256 = miniscript::hash256::Hash;
    type Ripemd160 = bitcoin::hashes::ripemd160::Hash;
    type Hash160 = bitcoin::hashes::hash160::Hash;
}
