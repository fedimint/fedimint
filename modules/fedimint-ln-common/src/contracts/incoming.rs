use std::io::Error;

use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::{hash_newtype, Hash as BitcoinHash};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{Amount, OutPoint};
use serde::{Deserialize, Serialize};

use crate::contracts::{ContractId, DecryptedPreimage, EncryptedPreimage, IdentifiableContract};
use crate::LightningInput;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractOffer {
    /// Amount for which the user is willing to sell the preimage
    pub amount: fedimint_core::Amount,
    pub hash: bitcoin_hashes::sha256::Hash,
    pub encrypted_preimage: EncryptedPreimage,
    pub expiry_time: Option<u64>,
}

impl IncomingContractOffer {
    pub fn id(&self) -> OfferId {
        OfferId::from_hash(self.hash)
    }
}

// FIXME: the protocol currently envisions the use of a pub key as preimage.
// This is bad for privacy though since pub keys are distinguishable from
// randomness and the payer would learn the recipient is using a federated mint.
// Probably best to just hash the key before.

// FIXME: encrypt preimage to LN gateway?

/// Specialized smart contract for incoming payments
///
/// A user generates a private/public keypair that can later be used to claim
/// the incoming funds. The public key is defined as the preimage of a
/// payment hash and threshold-encrypted to the federation's public key. They
/// then put up the encrypted preimage for sale by creating an
/// [`IncomingContractOffer`].
///
/// A lightning gateway wanting to claim an incoming HTLC can now use the offer
/// to buy the preimage by transferring funds into the corresponding contract.
/// This activates the threshold decryption process inside the federation. Since
/// the user could have threshold-encrypted useless data there are two possible
/// outcomes:
///
///   1. The decryption results in a valid preimage which is given to the
/// lightning gateway. The      user can in return claim the funds from the
/// contract. For this they need to be able to sign      with the private key
/// corresponding to the public key which they used as preimage.
///   2. The decryption results in an invalid preimage, the gateway can claim
/// back the money. For      this to work securely they have to specify a public
/// key when creating the actual contract.
// TODO: don't duplicate offer, include id instead and fetch offer on mint side
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContract {
    /// Payment hash which's corresponding preimage is being sold
    pub hash: bitcoin_hashes::sha256::Hash,
    /// Encrypted preimage as specified in offer
    pub encrypted_preimage: EncryptedPreimage,
    /// Status of preimage decryption, will either end in failure or contain the
    /// preimage eventually. In case decryption was successful the preimage
    /// is also the public key locking the contract, allowing the offer
    /// creator to redeem their money.
    pub decrypted_preimage: DecryptedPreimage,
    /// Key that can unlock contract in case the decrypted preimage was invalid
    pub gateway_key: secp256k1::PublicKey,
}

/// The funded version of an [`IncomingContract`] contains the [`OutPoint`] of
/// it's creation. Since this kind of contract can only be funded once this out
/// point is unambiguous. The out point is used to update the output outcome
/// once decryption finishes.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct FundedIncomingContract {
    pub contract: IncomingContract,
    /// Incoming contracts are funded exactly once, so they have an associated
    /// out-point. We use it to report the outcome of the preimage
    /// decryption started by the funding in the output's outcome (This can
    /// already be queried by users, making an additional way of querying
    /// contract states unnecessary for now).
    pub out_point: OutPoint,
}

hash_newtype!(
    OfferId,
    Sha256,
    32,
    doc = "The hash of a LN incoming contract offer"
);

impl IdentifiableContract for IncomingContract {
    fn contract_id(&self) -> ContractId {
        ContractId::from_hash(self.hash)
    }
}

impl Encodable for OfferId {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.as_inner().consensus_encode(writer)
    }
}

impl Decodable for OfferId {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(OfferId::from_inner(Decodable::consensus_decode(
            d, modules,
        )?))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct IncomingContractAccount {
    pub amount: Amount,
    pub contract: IncomingContract,
}

impl IncomingContractAccount {
    pub fn claim(&self) -> LightningInput {
        LightningInput::new_v0(self.contract.contract_id(), self.amount, None)
    }
}
