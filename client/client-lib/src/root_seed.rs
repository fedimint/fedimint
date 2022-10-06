use std::io::Write;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::SecretKey;
use secp256k1_zkp::{Secp256k1, Signing};

/// Root Key from which we derive deterministic yet unpredictable secrets
///
/// This is a core functionality for backup/restore functionality. In essence
/// it computes "random" as  `X = sha255(root_secret || purpose-salt || id)`.
pub struct RootSeed {
    // TODO: wrap in some secret protecting wrappers maybe?
    root_secret: [u8; 32],
}

impl RootSeed {
    fn get_blinding_nonce_hash(&self, seq: u64) -> sha256::Hash {
        let mut hash_engine = sha256::HashEngine::default();

        hash_engine
            .write_all(&self.root_secret)
            .expect("can't fail");
        hash_engine
            .write_all(b"FEDIMINT_DETERMINISTIC_BLINDING_NONCE")
            .expect("can't fail");
        hash_engine
            .write_all(&seq.to_le_bytes())
            .expect("can't fail");

        sha256::Hash::from_engine(hash_engine)
    }

    pub fn get_blinding_nonce_keypair<C>(&self, ctx: &Secp256k1<C>, seq: u64) -> bitcoin::KeyPair
    where
        C: Signing,
    {
        bitcoin::KeyPair::from_secret_key(ctx, SecretKey::from_slice(&self.get_blinding_nonce_hash(seq))
            .expect("can't fail: The probability of choosing a 32-byte string uniformly at random which is an invalid secret key is negligible"))
    }
}
