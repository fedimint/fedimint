use std::io::{Error, Write};
use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::PublicKey;
use fedimint_core::encoding::{Decodable, Encodable};
use miniscript::{MiniscriptKey, ToPublicKey};
use secp256k1::Signing;
use serde::{Deserialize, Serialize};

use crate::tweakable::{Contract, Tweakable};

#[derive(
    Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable,
)]
pub struct CompressedPublicKey {
    pub key: secp256k1::PublicKey,
}

impl CompressedPublicKey {
    pub fn new(key: secp256k1::PublicKey) -> Self {
        CompressedPublicKey { key }
    }
}

impl Encodable for CompressedPublicKey {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.key.serialize().consensus_encode(writer)
    }
}

impl MiniscriptKey for CompressedPublicKey {
    fn is_uncompressed(&self) -> bool {
        false
    }

    type RawPkHash = CompressedPublicKey;
    type Sha256 = bitcoin::hashes::sha256::Hash;
    type Hash256 = miniscript::hash256::Hash;
    type Ripemd160 = bitcoin::hashes::ripemd160::Hash;
    type Hash160 = bitcoin::hashes::hash160::Hash;

    fn to_pubkeyhash(&self) -> Self::RawPkHash {
        *self
    }
}

impl ToPublicKey for CompressedPublicKey {
    fn to_public_key(&self) -> PublicKey {
        PublicKey {
            compressed: true,
            inner: self.key,
        }
    }

    fn hash_to_hash160(hash: &Self::RawPkHash) -> bitcoin::hashes::hash160::Hash {
        bitcoin::hashes::hash160::Hash::hash(&hash.key.serialize()[..])
    }

    fn to_sha256(hash: &<Self as MiniscriptKey>::Sha256) -> bitcoin::hashes::sha256::Hash {
        *hash
    }

    fn to_hash256(hash: &<Self as MiniscriptKey>::Hash256) -> miniscript::hash256::Hash {
        *hash
    }

    fn to_ripemd160(hash: &<Self as MiniscriptKey>::Ripemd160) -> bitcoin::hashes::ripemd160::Hash {
        *hash
    }

    fn to_hash160(hash: &<Self as MiniscriptKey>::Hash160) -> bitcoin::hashes::hash160::Hash {
        *hash
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
    fn tweak<Ctx: Verification + Signing, Ctr: Contract>(
        &self,
        tweak: &Ctr,
        secp: &Secp256k1<Ctx>,
    ) -> Self {
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
