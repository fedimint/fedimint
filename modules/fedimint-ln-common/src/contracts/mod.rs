pub mod incoming;
pub mod outgoing;

use std::io::Error;

use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::{hash_newtype, Hash as BitcoinHash};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::OutPoint;
use serde::{Deserialize, Serialize};

/// Anything representing a contract which thus has an associated [`ContractId`]
pub trait IdentifiableContract: Encodable {
    fn contract_id(&self) -> ContractId;
}

hash_newtype!(
    ContractId,
    Sha256,
    32,
    doc = "The hash of a LN incoming contract"
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
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.as_inner().consensus_encode(writer)
    }
}

impl Decodable for ContractId {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(ContractId::from_inner(Decodable::consensus_decode(
            d, modules,
        )?))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Preimage(pub [u8; 32]);

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
            DecryptedPreimage::Some(_) => true,
            DecryptedPreimage::Invalid => true,
        }
    }
}
/// Threshold-encrypted [`Preimage`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Deserialize, Serialize)]
pub struct EncryptedPreimage(pub threshold_crypto::Ciphertext);

/// Share to decrypt an [`EncryptedPreimage`]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct PreimageDecryptionShare(pub threshold_crypto::DecryptionShare);

impl EncryptedPreimage {
    pub fn new(preimage_key: PreimageKey, key: &threshold_crypto::PublicKey) -> EncryptedPreimage {
        EncryptedPreimage(key.encrypt(preimage_key.0))
    }
}
