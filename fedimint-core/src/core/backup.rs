use std::fmt::Debug;

use bitcoin::hashes::{sha256, Hash};
use fedimint_core::encoding::{Decodable, Encodable};
use secp256k1::{Keypair, Message, Secp256k1, Signing, Verification};
use serde::{Deserialize, Serialize};

/// Maximum payload size of a backup request
///
/// Note: this is just a current hard limit,
/// that could be changed in the future versions.
///
/// For comparison - at the time of writing, ecash module
/// backup with 52 notes is around 5.1K.
pub const BACKUP_REQUEST_MAX_PAYLOAD_SIZE_BYTES: usize = 128 * 1024;

#[derive(Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct BackupRequest {
    pub id: secp256k1::PublicKey,
    #[serde(with = "fedimint_core::hex::serde")]
    pub payload: Vec<u8>,
    pub timestamp: std::time::SystemTime,
}

impl BackupRequest {
    fn hash(&self) -> sha256::Hash {
        self.consensus_hash()
    }

    pub fn sign(self, keypair: &Keypair) -> anyhow::Result<SignedBackupRequest> {
        let signature = secp256k1::SECP256K1
            .sign_schnorr(&Message::from_digest(*self.hash().as_ref()), keypair);

        Ok(SignedBackupRequest {
            request: self,
            signature,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedBackupRequest {
    #[serde(flatten)]
    request: BackupRequest,
    pub signature: secp256k1::schnorr::Signature,
}

impl SignedBackupRequest {
    pub fn verify_valid<C>(&self, ctx: &Secp256k1<C>) -> Result<&BackupRequest, secp256k1::Error>
    where
        C: Signing + Verification,
    {
        ctx.verify_schnorr(
            &self.signature,
            &secp256k1::Message::from_digest_slice(&self.request.hash().to_byte_array())
                .expect("Can't fail"),
            &self.request.id.x_only_public_key().0,
        )?;

        Ok(&self.request)
    }
}
