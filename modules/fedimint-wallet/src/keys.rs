use crate::tweakable::{Contract, Tweakable};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::PublicKey;
use miniscript::{MiniscriptKey, ToPublicKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CompressedPublicKey {
    pub key: secp256k1::PublicKey,
}

impl CompressedPublicKey {
    pub fn new(key: secp256k1::PublicKey) -> Self {
        CompressedPublicKey { key }
    }
}

impl MiniscriptKey for CompressedPublicKey {
    fn is_uncompressed(&self) -> bool {
        false
    }

    type Hash = CompressedPublicKey;

    fn to_pubkeyhash(&self) -> Self::Hash {
        (*self).clone()
    }
}

impl ToPublicKey for CompressedPublicKey {
    fn to_public_key(&self) -> PublicKey {
        PublicKey {
            compressed: true,
            inner: self.key,
        }
    }

    fn hash_to_hash160(hash: &Self::Hash) -> bitcoin::hashes::hash160::Hash {
        bitcoin::hashes::hash160::Hash::hash(&hash.key.serialize()[..])
    }
}

impl std::fmt::Display for CompressedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.key, f)
    }
}

impl FromStr for CompressedPublicKey {
    type Err = secp256k1::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(CompressedPublicKey {
            key: secp256k1::PublicKey::from_str(s)?,
        })
    }
}

impl Tweakable for CompressedPublicKey {
    fn tweak<Ctx: Verification, Ctr: Contract>(&self, tweak: &Ctr, secp: &Secp256k1<Ctx>) -> Self {
        CompressedPublicKey {
            key: self.key.tweak(tweak, secp),
        }
    }
}

impl From<CompressedPublicKey> for bitcoin::PublicKey {
    fn from(key: CompressedPublicKey) -> Self {
        bitcoin::PublicKey {
            compressed: true,
            inner: key.key,
        }
    }
}
