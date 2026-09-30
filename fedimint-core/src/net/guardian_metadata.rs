use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::Message;
use fedimint_core::encoding::{Decodable, DecodeContext as _, DecodeError, Encodable};
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
    /// Iroh-next 1.0-compatible API endpoint node ID (public key) when enabled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh_next_endpoint: Option<String>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct SignedGuardianMetadata {
    /// The raw bytes that were signed (JSON-encoded GuardianMetadata)
    pub bytes: Vec<u8>,
    /// The parsed GuardianMetadata value
    pub value: GuardianMetadata,
    pub signature: secp256k1::schnorr::Signature,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq, Encodable, Decodable)]
pub struct SignedGuardianMetadataSubmission {
    #[serde(flatten)]
    pub signed_guardian_metadata: SignedGuardianMetadata,
    pub peer_id: crate::PeerId,
}

// Implement Serialize/Deserialize for SignedGuardianMetadata for JSON
//
// Format: {"content": "<json string>", "signature": "<hex-encoded signature>"}
// The `content` field contains the exact JSON string that was signed (preserved
// byte-for-byte). The `signature` field contains the hex-encoded Schnorr
// signature over the content bytes.
impl Serialize for SignedGuardianMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SignedGuardianMetadata", 2)?;

        // Serialize bytes as a UTF-8 string (content field)
        let content = String::from_utf8(self.bytes.clone())
            .map_err(|e| serde::ser::Error::custom(format!("Invalid UTF-8 in bytes: {e}")))?;
        state.serialize_field("content", &content)?;

        // Serialize signature as hex string
        state.serialize_field("signature", &hex::encode(self.signature.as_ref()))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SignedGuardianMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct SignedGuardianMetadataHelper {
            content: String,
            signature: String,
        }

        let helper = SignedGuardianMetadataHelper::deserialize(deserializer)?;

        let bytes = helper.content.into_bytes();
        let value: GuardianMetadata = serde_json::from_slice(&bytes).map_err(D::Error::custom)?;
        let signature_bytes = hex::decode(&helper.signature).map_err(D::Error::custom)?;
        let signature = secp256k1::schnorr::Signature::from_slice(&signature_bytes)
            .map_err(D::Error::custom)?;

        Ok(Self {
            bytes,
            value,
            signature,
        })
    }
}

// Implement Encodable/Decodable for SignedGuardianMetadata only
impl Encodable for SignedGuardianMetadata {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        // Encode the bytes and signature (value is derived from bytes)
        self.bytes.consensus_encode(writer)?;
        self.signature.consensus_encode(writer)?;
        Ok(())
    }
}

impl Decodable for SignedGuardianMetadata {
    fn consensus_decode_partial_from_finite_reader<R: std::io::Read>(
        reader: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial_from_finite_reader(reader, modules)?;
        let value: GuardianMetadata = serde_json::from_slice(&bytes)
            .map_err(DecodeError::from_err)
            .context("Invalid JSON")?;
        let signature = secp256k1::schnorr::Signature::consensus_decode_partial_from_finite_reader(
            reader, modules,
        )?;

        Ok(Self {
            bytes,
            value,
            signature,
        })
    }
}

fn compute_tagged_hash(json_bytes: &[u8]) -> sha256::Hash {
    use bitcoin::hashes::HashEngine;
    let mut engine = sha256::HashEngine::default();
    engine.input(GUARDIAN_METADATA_MESSAGE_TAG);
    engine.input(json_bytes);
    sha256::Hash::from_engine(engine)
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("Invalid signature")]
    InvalidSignature,
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
            iroh_next_endpoint: None,
        }
    }

    /// Set the iroh-next 1.0-compatible API endpoint node ID.
    pub fn with_iroh_next_endpoint(mut self, endpoint: String) -> Self {
        self.iroh_next_endpoint = Some(endpoint);
        self
    }

    pub fn sign<C: secp256k1::Signing>(
        &self,
        ctx: &secp256k1::Secp256k1<C>,
        key: &secp256k1::Keypair,
    ) -> SignedGuardianMetadata {
        // Serialize to JSON and compute tagged hash
        let bytes = serde_json::to_vec(self).expect("JSON serialization should not fail");
        let tagged_hash = compute_tagged_hash(&bytes);

        let msg = Message::from_digest(*tagged_hash.as_ref());
        let signature = ctx.sign_schnorr(&msg, key);

        SignedGuardianMetadata {
            bytes,
            value: self.clone(),
            signature,
        }
    }
}

impl SignedGuardianMetadata {
    /// Returns the parsed GuardianMetadata value
    pub fn guardian_metadata(&self) -> &GuardianMetadata {
        &self.value
    }

    /// Compute the tagged hash from the stored bytes
    pub fn tagged_hash(&self) -> sha256::Hash {
        compute_tagged_hash(&self.bytes)
    }

    /// Verifies the signature and timestamp validity.
    ///
    /// Returns `Ok(())` if the signature is valid for the given public key and
    /// the timestamp is not too far in the future relative to `now`.
    pub fn verify<C: secp256k1::Verification>(
        &self,
        ctx: &secp256k1::Secp256k1<C>,
        pk: &secp256k1::PublicKey,
        now: std::time::Duration,
    ) -> Result<(), VerificationError> {
        // First check the signature
        let msg = Message::from_digest(*self.tagged_hash().as_ref());
        ctx.verify_schnorr(&self.signature, &msg, &pk.x_only_public_key().0)
            .map_err(|_| VerificationError::InvalidSignature)?;

        // Then check the timestamp isn't too far in the future
        let current_secs = now.as_secs();
        let max_allowed_timestamp = current_secs.saturating_add(MAX_FUTURE_TIMESTAMP_SECS);

        if max_allowed_timestamp < self.value.timestamp_secs {
            return Err(VerificationError::TimestampTooFarInFuture {
                timestamp_secs: self.value.timestamp_secs,
                max_allowed: max_allowed_timestamp,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
