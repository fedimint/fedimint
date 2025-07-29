pub mod incoming;
pub mod outgoing;

use std::fmt::Display;
use std::io::Error;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash as BitcoinHash, hash_newtype};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::hex::ToHex;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{OutPoint, secp256k1};
use serde::{Deserialize, Serialize};

/// Anything representing a contract which thus has an associated [`ContractId`]
pub trait IdentifiableContract: Encodable {
    fn contract_id(&self) -> ContractId;
}

hash_newtype!(
    /// The hash of a LN incoming contract
    pub struct ContractId(Sha256);
);

/// A contract before execution as found in transaction outputs
// TODO: investigate if this is actually a problem
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum Contract {
    Incoming(incoming::IncomingContract),
    Outgoing(outgoing::OutgoingContract),
}

/// A contract after execution as saved in the database
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub enum FundedContract {
    Incoming(incoming::FundedIncomingContract),
    Outgoing(outgoing::OutgoingContract),
}

/// Outcome of a contract. Only incoming contracts currently need to communicate
/// anything back to the user (the decrypted preimage).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum ContractOutcome {
    Incoming(DecryptedPreimage),
    Outgoing(OutgoingContractOutcome),
}

impl ContractOutcome {
    pub fn is_permanent(&self) -> bool {
        match self {
            ContractOutcome::Incoming(o) => o.is_permanent(),
            ContractOutcome::Outgoing(_) => true,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct OutgoingContractOutcome {}

impl IdentifiableContract for Contract {
    fn contract_id(&self) -> ContractId {
        match self {
            Contract::Incoming(c) => c.contract_id(),
            Contract::Outgoing(c) => c.contract_id(),
        }
    }
}

impl IdentifiableContract for FundedContract {
    fn contract_id(&self) -> ContractId {
        match self {
            FundedContract::Incoming(c) => c.contract.contract_id(),
            FundedContract::Outgoing(c) => c.contract_id(),
        }
    }
}

impl Contract {
    /// Creates the initial contract outcome that is created on transaction
    /// acceptance. Depending on the contract type it is not yet final.
    pub fn to_outcome(&self) -> ContractOutcome {
        match self {
            Contract::Incoming(_) => ContractOutcome::Incoming(DecryptedPreimage::Pending),
            Contract::Outgoing(_) => ContractOutcome::Outgoing(OutgoingContractOutcome {}),
        }
    }

    /// Converts a contract to its executed version.
    pub fn to_funded(self, out_point: OutPoint) -> FundedContract {
        match self {
            Contract::Incoming(incoming) => {
                FundedContract::Incoming(incoming::FundedIncomingContract {
                    contract: incoming,
                    out_point,
                })
            }
            Contract::Outgoing(outgoing) => FundedContract::Outgoing(outgoing),
        }
    }
}

impl Encodable for ContractId {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.to_byte_array().consensus_encode(writer)
    }
}

impl Decodable for ContractId {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(ContractId::from_byte_array(
            Decodable::consensus_decode_partial(d, modules)?,
        ))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Preimage(pub [u8; 32]);

impl Display for Preimage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.encode_hex::<String>())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PreimageKey(#[serde(with = "serde_big_array::BigArray")] pub [u8; 33]);

impl PreimageKey {
    /// Create a Schnorr public key
    ///
    /// # Errors
    ///
    /// Returns [`secp256k1::Error::InvalidPublicKey`] if the Preimage does not
    /// represent a valid Secp256k1 point x coordinate.
    pub fn to_public_key(&self) -> Result<secp256k1::PublicKey, secp256k1::Error> {
        secp256k1::PublicKey::from_slice(&self.0)
    }
}

/// Current status of preimage decryption
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum DecryptedPreimageStatus {
    /// There aren't enough decryption shares yet
    Pending,
    /// The decrypted preimage was valid
    Some(Preimage),
    /// The decrypted preimage was invalid
    Invalid,
}

/// Possible outcomes of preimage decryption
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum DecryptedPreimage {
    /// There aren't enough decryption shares yet
    Pending,
    /// The decrypted preimage was valid
    Some(PreimageKey),
    /// The decrypted preimage was invalid
    Invalid,
}

impl DecryptedPreimage {
    pub fn is_permanent(&self) -> bool {
        match self {
            DecryptedPreimage::Pending => false,
            DecryptedPreimage::Some(_) | DecryptedPreimage::Invalid => true,
        }
    }
}
/// Threshold-encrypted [`Preimage`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Deserialize, Serialize)]
pub struct EncryptedPreimage(pub threshold_crypto::Ciphertext);

impl From<EncryptedPreimage> for EncryptedPreimageUndecoded {
    fn from(value: EncryptedPreimage) -> Self {
        EncryptedPreimageUndecoded {
            bytes: value.0.to_bytes(),
        }
    }
}
/// Share to decrypt an [`EncryptedPreimage`]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct PreimageDecryptionShare(pub threshold_crypto::DecryptionShare);

impl EncryptedPreimage {
    pub fn new(preimage_key: &PreimageKey, key: &threshold_crypto::PublicKey) -> EncryptedPreimage {
        EncryptedPreimage(key.encrypt(preimage_key.0))
    }
}

/// Undecoded version of [`EncryptedPreimage`] that stores raw bytes to defer
/// expensive cryptographic validation during decoding until actually needed.
///
/// This follows the same pattern as [`SpendableNoteUndecoded`] - stores the
/// ciphertext as raw bytes to avoid the cost of
/// `threshold_crypto::Ciphertext::from_bytes()` validation when the encrypted
/// preimage might be filtered out or unused.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct EncryptedPreimageUndecoded {
    /// Raw bytes of the threshold_crypto::Ciphertext, kept in sync with the
    /// encoded format
    pub bytes: Vec<u8>,
}

impl EncryptedPreimageUndecoded {
    /// Create from an already-decoded EncryptedPreimage
    pub fn from_decoded(encrypted_preimage: &EncryptedPreimage) -> Self {
        Self {
            bytes: encrypted_preimage.0.to_bytes(),
        }
    }

    /// Decode into EncryptedPreimage, performing expensive cryptographic
    /// validation
    pub fn decode(&self) -> anyhow::Result<EncryptedPreimage> {
        let ciphertext = threshold_crypto::Ciphertext::from_bytes(&self.bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid ciphertext bytes"))?;
        Ok(EncryptedPreimage(ciphertext))
    }
}
