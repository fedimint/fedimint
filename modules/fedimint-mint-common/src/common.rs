use std::fmt::Debug;

use bitcoin_hashes::sha256;
use fedimint_core::bitcoin_migration::{
    bitcoin29_to_bitcoin30_schnorr_signature, bitcoin29_to_bitcoin30_secp256k1_public_key,
    bitcoin29_to_bitcoin30_sha256_hash, bitcoin30_to_bitcoin29_keypair,
    bitcoin30_to_bitcoin29_message,
};
use fedimint_core::encoding::{Decodable, Encodable};
use secp256k1_zkp::{KeyPair, Message, Secp256k1, Signing, Verification};
use serde::{Deserialize, Serialize};

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

    pub fn sign(self, keypair: &KeyPair) -> anyhow::Result<SignedBackupRequest> {
        let signature = secp256k1::SECP256K1.sign_schnorr(
            &bitcoin30_to_bitcoin29_message(Message::from(bitcoin29_to_bitcoin30_sha256_hash(
                self.hash(),
            ))),
            &bitcoin30_to_bitcoin29_keypair(*keypair),
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
    #[serde(with = "::fedimint_core::encoding::as_hex")]
    pub signature: secp256k1::schnorr::Signature,
}

impl SignedBackupRequest {
    pub fn verify_valid<C>(
        &self,
        ctx: &Secp256k1<C>,
    ) -> Result<&BackupRequest, secp256k1_zkp::Error>
    where
        C: Signing + Verification,
    {
        ctx.verify_schnorr(
            &bitcoin29_to_bitcoin30_schnorr_signature(self.signature),
            &Message::from_slice(&self.request.hash()).expect("Can't fail"),
            &bitcoin29_to_bitcoin30_secp256k1_public_key(self.request.id)
                .x_only_public_key()
                .0,
        )?;

        Ok(&self.request)
    }
}
