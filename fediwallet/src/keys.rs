use bitcoin::hashes::Hash;
use bitcoin::PublicKey;
use miniscript::{MiniscriptKey, ToPublicKey};

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct CompressedPublicKey {
    pub(crate) key: secp256k1::PublicKey,
}

impl MiniscriptKey for CompressedPublicKey {
    type Hash = CompressedPublicKey;

    fn is_uncompressed(&self) -> bool {
        false
    }

    fn to_pubkeyhash(&self) -> Self::Hash {
        (*self).clone()
    }

    fn serialized_len(&self) -> usize {
        secp256k1::constants::PUBLIC_KEY_SIZE
    }
}

impl ToPublicKey for CompressedPublicKey {
    fn to_public_key(&self) -> PublicKey {
        PublicKey {
            compressed: true,
            key: self.key.clone(),
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
