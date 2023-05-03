use std::fmt::Debug;

use bitcoin::secp256k1;
use bitcoin_hashes::sha256;
use fedimint_core::encoding::{Decodable, Encodable};
use secp256k1_zkp::{KeyPair, Message, Secp256k1, Signing, Verification};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct BackupRequest {
    pub id: secp256k1::XOnlyPublicKey,
    #[serde(with = "fedimint_core::hex::serde")]
    pub payload: Vec<u8>,
    pub timestamp: std::time::SystemTime,
}

impl BackupRequest {
    fn hash(&self) -> sha256::Hash {
        self.consensus_hash()
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
