use bitcoin::{secp256k1, KeyPair};
use bitcoin_hashes::{sha256, Hash};
use secp256k1_zkp::{Message, Secp256k1, Signing, Verification};
use serde::{Deserialize, Serialize};

use crate::encoding::{Decodable, Encodable};

#[derive(Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct BackupRequest {
    pub id: secp256k1::XOnlyPublicKey,
    pub timestamp: std::time::SystemTime,
    #[serde(with = "hex::serde")]
    pub payload: Vec<u8>,
}

impl BackupRequest {
    fn hash(&self) -> sha256::Hash {
        let mut sha = sha256::HashEngine::default();

        self.consensus_encode(&mut sha)
            .expect("Encoding to hash engine can't fail");

        sha256::Hash::from_engine(sha)
    }

    pub fn sign(self, keypair: &KeyPair) -> anyhow::Result<SignedBackupRequest> {
        let signature = secp256k1::SECP256K1.sign_schnorr(&Message::from(self.hash()), keypair);

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
            &Message::from_slice(&self.request.hash()).expect("Can't fail"),
            &self.request.id,
        )?;

        Ok(&self.request)
    }
}
