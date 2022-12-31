use std::fmt::Debug;
use std::io;

use bitcoin_hashes::{sha256, Hash};
use fedimint_api::core::{ConsensusItem, Input, Output, OutputOutcome, PluginDecode};
use fedimint_api::encoding::DecodeError;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::module::registry::ModuleDecoderRegistry;
use secp256k1_zkp::{KeyPair, Message, Secp256k1, Signing, Verification};
use serde::{Deserialize, Serialize};

use crate::{MintInput, MintOutput, MintOutputConfirmation, MintOutputOutcome};

#[derive(Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct BackupRequest {
    pub id: secp256k1::XOnlyPublicKey,
    #[serde(with = "hex::serde")]
    pub payload: Vec<u8>,
    pub timestamp: std::time::SystemTime,
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

#[derive(Debug, Default, Clone)]
pub struct MintModuleDecoder;

impl PluginDecode for MintModuleDecoder {
    fn decode_input(mut d: &mut dyn io::Read) -> Result<Input, DecodeError> {
        Ok(Input::from(MintInput::consensus_decode(
            &mut d,
            &ModuleDecoderRegistry::default(),
        )?))
    }
    fn decode_output(mut d: &mut dyn io::Read) -> Result<Output, DecodeError> {
        Ok(Output::from(MintOutput::consensus_decode(
            &mut d,
            &ModuleDecoderRegistry::default(),
        )?))
    }

    fn decode_output_outcome(mut d: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        Ok(OutputOutcome::from(MintOutputOutcome::consensus_decode(
            &mut d,
            &ModuleDecoderRegistry::default(),
        )?))
    }

    fn decode_consensus_item(
        mut r: &mut dyn io::Read,
    ) -> Result<fedimint_api::core::ConsensusItem, DecodeError> {
        Ok(ConsensusItem::from(
            MintOutputConfirmation::consensus_decode(&mut r, &ModuleDecoderRegistry::default())?,
        ))
    }
}
