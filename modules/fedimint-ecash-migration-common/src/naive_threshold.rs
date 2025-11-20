//! Naive threshold signature scheme implementation using concatenated Schnorr
//! signatures.

use fedimint_core::encoding::{Decodable, Encodable};
use secp256k1::schnorr::Signature;
use secp256k1::{Message, PublicKey};
use serde::{Deserialize, Serialize};

/// A naive threshold signature scheme public key containing all public and the
/// threshold number of signatures required to verify a signature.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct NaiveThresholdKey {
    threshold: u64,
    public_keys: Vec<PublicKey>,
}

/// A naive threshold signature scheme signature containing a cooncatenated list
/// of signatures.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct NaiveThresholdSignature {
    /// A concatenated list of signatures. Has to contain at least the threshold
    /// number of signatures. The remaining signatures can be `None`.
    signatures: Vec<Option<Signature>>,
}

impl NaiveThresholdKey {
    /// Create a new naive threshold signature scheme public key with a single
    /// public key and a threshold of 1.
    pub fn new_single(public_key: PublicKey) -> Self {
        Self {
            threshold: 1,
            public_keys: vec![public_key],
        }
    }

    /// Create a new naive threshold signature scheme public key with a
    /// threshold number of public keys and a threshold number of signatures
    /// required to verify a signature.
    ///
    /// # Panics
    /// Panics if the threshold is less than 1, the public keys are empty, or
    /// the threshold is greater than the number of public keys.
    pub fn new_threshold(threshold: u64, public_keys: Vec<PublicKey>) -> Self {
        assert!(threshold > 0, "Threshold must be greater than 0");
        assert!(!public_keys.is_empty(), "Public keys must not be empty");
        assert!(
            threshold <= public_keys.len() as u64,
            "Threshold must be less than or equal to the number of public keys"
        );

        Self {
            threshold,
            public_keys,
        }
    }
}

impl NaiveThresholdSignature {
    pub fn new(signatures: Vec<Option<Signature>>) -> Self {
        Self { signatures }
    }

    /// Verify the signature of the given message under a public key.
    #[must_use]
    pub fn verify(&self, message: Message, pub_key: &NaiveThresholdKey) -> bool {
        if pub_key.public_keys.len() != self.signatures.len() {
            return false;
        }

        if (self
            .signatures
            .iter()
            .filter(|signature| signature.is_some())
            .count() as u64)
            < pub_key.threshold
        {
            return false;
        }

        self.signatures
            .iter()
            .zip(pub_key.public_keys.iter())
            .all(|(signature, public_key)| {
                if let Some(signature) = signature {
                    signature
                        .verify(&message, &public_key.x_only_public_key().0)
                        .is_ok()
                } else {
                    true
                }
            })
    }
}
