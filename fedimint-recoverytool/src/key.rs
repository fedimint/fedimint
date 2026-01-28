use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::hash::Hasher;

use fedimint_wallet_server::common::keys::CompressedPublicKey;
use miniscript::MiniscriptKey;

/// `MiniscriptKey` that is either a WIF-encoded private key or a compressed,
/// hex-encoded public key
#[derive(Clone, Copy, Eq)]
pub enum Key {
    Public(CompressedPublicKey),
    Private(bitcoin::key::PrivateKey),
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Public(pk) => f.debug_tuple("Key::Public").field(pk).finish(),
            Key::Private(sk) => {
                if fedimint_core::fmt_utils::show_secrets() || f.alternate() {
                    f.debug_tuple("Key::Private").field(sk).finish()
                } else {
                    f.debug_tuple("Key::Private").field(&"<redacted>").finish()
                }
            }
        }
    }
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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
            Key::Private(sk) => CompressedPublicKey::new(
                bitcoin::secp256k1::PublicKey::from_secret_key_global(&sk.inner),
            ),
        }
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Public(pk) => Display::fmt(pk, f),
            Key::Private(sk) => {
                if fedimint_core::fmt_utils::show_secrets() || f.alternate() {
                    Display::fmt(sk, f)
                } else {
                    // Show only the public key derived from the private key
                    let pk = CompressedPublicKey::new(
                        bitcoin::secp256k1::PublicKey::from_secret_key_global(&sk.inner),
                    );
                    write!(f, "<private key for {pk}>")
                }
            }
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
