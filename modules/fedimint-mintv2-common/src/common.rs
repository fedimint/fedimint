use std::fmt::Debug;

use bitcoin_hashes::{sha256, Hash};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1;
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, Signing, Verification, SECP256K1};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct BackupRequest {
    pub id: PublicKey,
    #[serde(with = "fedimint_core::hex::serde")]
    pub payload: Vec<u8>,
    pub timestamp: std::time::SystemTime,
}

impl BackupRequest {
    fn hash(&self) -> sha256::Hash {
        self.consensus_hash()
    }

    pub fn sign(self, keypair: &Keypair) -> anyhow::Result<SignedBackupRequest> {
        let signature =
            SECP256K1.sign_schnorr(&Message::from_digest(*self.hash().as_ref()), keypair);

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
    #[serde(with = "::fedimint_core::encoding::as_hex")]
    pub signature: fedimint_core::secp256k1::schnorr::Signature,
}

impl SignedBackupRequest {
    pub fn verify_valid<C>(&self, ctx: &Secp256k1<C>) -> Result<&BackupRequest, secp256k1::Error>
    where
        C: Signing + Verification,
    {
        ctx.verify_schnorr(
            &self.signature,
            &Message::from_digest_slice(&self.request.hash().to_byte_array()).expect("Can't fail"),
            &self.request.id.x_only_public_key().0,
        )?;

        Ok(&self.request)
    }
}
