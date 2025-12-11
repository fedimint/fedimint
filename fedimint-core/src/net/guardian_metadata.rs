use std::time::UNIX_EPOCH;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::Message;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use serde::{Deserialize, Serialize};

use crate::util::SafeUrl;

const GUARDIAN_METADATA_MESSAGE_TAG: &[u8] = b"fedimint-guardian-metadata";
/// Allow messages with timestamps up to 1 hour in the future
const MAX_FUTURE_TIMESTAMP_SECS: u64 = 3600;

#[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq)]
pub struct GuardianMetadata {
    pub api_urls: Vec<SafeUrl>,
    /// z-base32 encoded Pkarr id
    pub pkarr_id_z32: String,
    pub timestamp_secs: u64,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct SignedGuardianMetadata {
    pub json_bytes: Vec<u8>,
    pub signature: secp256k1::schnorr::Signature,
}

// Implement Encodable/Decodable for SignedGuardianMetadata only
impl Encodable for SignedGuardianMetadata {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        // Encode the JSON bytes and signature
        self.json_bytes.consensus_encode(writer)?;
        self.signature.consensus_encode(writer)?;
        Ok(())
    }
}

impl Decodable for SignedGuardianMetadata {
    fn consensus_decode_partial_from_finite_reader<R: std::io::Read>(
        reader: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        // Decode the JSON bytes
        let json_bytes = Vec::<u8>::consensus_decode_partial_from_finite_reader(reader, modules)?;
        // Decode the signature
        let signature = secp256k1::schnorr::Signature::consensus_decode_partial_from_finite_reader(
            reader, modules,
        )?;

        Ok(Self {
            json_bytes,
            signature,
        })
    }
}

fn compute_tagged_hash(json_bytes: &[u8]) -> sha256::Hash {
    let mut msg = GUARDIAN_METADATA_MESSAGE_TAG.to_vec();
    msg.extend_from_slice(json_bytes);
    sha256::Hash::hash(&msg)
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("Failed to deserialize guardian metadata: {0}")]
    DeserializationError(#[from] serde_json::Error),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("System time error: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("Timestamp {timestamp_secs} is too far in the future (max allowed: {max_allowed})")]
    TimestampTooFarInFuture {
        timestamp_secs: u64,
        max_allowed: u64,
    },
}

impl GuardianMetadata {
    pub fn new(api_urls: Vec<SafeUrl>, pkarr_id_z32: String, timestamp_secs: u64) -> Self {
        Self {
            api_urls,
            pkarr_id_z32,
            timestamp_secs,
        }
    }

    pub fn sign<C: secp256k1::Signing>(
        &self,
        ctx: &secp256k1::Secp256k1<C>,
        key: &secp256k1::Keypair,
    ) -> SignedGuardianMetadata {
        // Serialize to JSON and compute tagged hash
        let json_bytes = serde_json::to_vec(self).expect("JSON serialization should not fail");
        let tagged_hash = compute_tagged_hash(&json_bytes);

        let msg = Message::from_digest(*tagged_hash.as_ref());
        let signature = ctx.sign_schnorr(&msg, key);

        SignedGuardianMetadata {
            json_bytes,
            signature,
        }
    }
}

impl SignedGuardianMetadata {
    /// Deserialize the GuardianMetadata from the stored JSON bytes
    pub fn guardian_metadata(&self) -> Result<GuardianMetadata, serde_json::Error> {
        serde_json::from_slice(&self.json_bytes)
    }

    /// Compute the tagged hash from the stored JSON bytes
    pub fn tagged_hash(&self) -> sha256::Hash {
        compute_tagged_hash(&self.json_bytes)
    }

    /// Verifies the signature and timestamp validity.
    ///
    /// Returns `Ok(())` if the signature is valid for the given public key and
    /// the timestamp is not too far in the future.
    pub fn verify<C: secp256k1::Verification>(
        &self,
        ctx: &secp256k1::Secp256k1<C>,
        pk: &secp256k1::PublicKey,
    ) -> Result<(), VerificationError> {
        // First check the signature
        let msg = Message::from_digest(*self.tagged_hash().as_ref());
        ctx.verify_schnorr(&self.signature, &msg, &pk.x_only_public_key().0)
            .map_err(|_| VerificationError::InvalidSignature)?;

        // Deserialize metadata (validates JSON)
        let metadata = self.guardian_metadata()?;

        // Then check the timestamp isn't too far in the future
        let current_time = crate::time::now().duration_since(UNIX_EPOCH)?;
        let current_secs = current_time.as_secs();
        let max_allowed_timestamp = current_secs.saturating_add(MAX_FUTURE_TIMESTAMP_SECS);

        if max_allowed_timestamp < metadata.timestamp_secs {
            return Err(VerificationError::TimestampTooFarInFuture {
                timestamp_secs: metadata.timestamp_secs,
                max_allowed: max_allowed_timestamp,
            });
        }

        Ok(())
    }
}
