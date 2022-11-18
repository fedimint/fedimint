use std::io::Write;

use bitcoin::{secp256k1, KeyPair};
use bitcoin_hashes::{sha256, Hash};
use secp256k1_zkp::{Message, SECP256K1};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupRequest {
    pub id: secp256k1::XOnlyPublicKey,
    // unix timestamp
    pub timestamp: u64,
    #[serde(with = "hex::serde")]
    pub payload: Vec<u8>,
}

impl BackupRequest {
    fn hash(&self) -> sha256::Hash {
        let mut sha = sha256::HashEngine::default();

        sha.write_all(&self.id.serialize()).expect("Can't fail");
        sha.write_all(&self.payload).expect("Can't fail");

        sha256::Hash::from_engine(sha)
    }

    pub fn sign(self, keypair: &KeyPair) -> anyhow::Result<SignedBackupRequest> {
        let signature = secp256k1::SECP256K1.sign_schnorr(
            &Message::from_slice(&self.hash()).expect("Can't fail"),
            keypair,
        );

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
    pub fn verify_valid(&self) -> Result<&BackupRequest, secp256k1::Error> {
        SECP256K1.verify_schnorr(
            &self.signature,
            &Message::from_slice(&self.request.hash()).expect("Can't fail"),
            &self.request.id,
        )?;

        Ok(&self.request)
    }
}
