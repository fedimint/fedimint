pub mod account;
pub mod incoming;
pub mod outgoing;

use crate::contracts::incoming::{DecryptedPreimage, FundedIncomingContract};
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::Hash as BitcoinHash;
use bitcoin_hashes::{borrow_slice_impl, hash_newtype, hex_fmt_impl, index_impl, serde_impl};
use minimint_api::encoding::{Decodable, DecodeError, Encodable};
use minimint_api::OutPoint;
use serde::{Deserialize, Serialize};
use std::io::Error;

/// Anything representing a contract which thus has an associated [`ContractId`]
pub trait IdentifyableContract: Encodable {
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
    Account(account::AccountContract),
    Incoming(incoming::IncomingContract),
    Outgoing(outgoing::OutgoingContract),
}

/// A contract after execution as saved in the database
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub enum FundedContract {
    Account(account::AccountContract),
    Incoming(incoming::FundedIncomingContract),
    Outgoing(outgoing::OutgoingContract),
}

/// Outcome of a contract. Only incoming contracts currently need to communicate anything back to
/// the user (the decrypted preimage).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum ContractOutcome {
    Account(AccountContractOutcome),
    Incoming(incoming::DecryptedPreimage),
    Outgoing(OutgoingContractOutcome),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct AccountContractOutcome {}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct OutgoingContractOutcome {}

impl IdentifyableContract for Contract {
    fn contract_id(&self) -> ContractId {
        match self {
            Contract::Account(c) => c.contract_id(),
            Contract::Incoming(c) => c.contract_id(),
            Contract::Outgoing(c) => c.contract_id(),
        }
    }
}

impl IdentifyableContract for FundedContract {
    fn contract_id(&self) -> ContractId {
        match self {
            FundedContract::Account(c) => c.contract_id(),
            FundedContract::Incoming(c) => c.contract.contract_id(),
            FundedContract::Outgoing(c) => c.contract_id(),
        }
    }
}

impl Contract {
    /// Creates the initial contract outcome that is created on transaction acceptance. Depending on
    /// the contract type it is not yet final.
    pub fn to_outcome(&self) -> ContractOutcome {
        match self {
            Contract::Account(_) => ContractOutcome::Account(AccountContractOutcome {}),
            Contract::Incoming(_) => ContractOutcome::Incoming(DecryptedPreimage::Pending),
            Contract::Outgoing(_) => ContractOutcome::Outgoing(OutgoingContractOutcome {}),
        }
    }

    /// Converts a contract to its executed version.
    pub fn to_funded(self, out_point: OutPoint) -> FundedContract {
        match self {
            Contract::Account(account) => FundedContract::Account(account),
            Contract::Incoming(incoming) => FundedContract::Incoming(FundedIncomingContract {
                contract: incoming,
                out_point,
            }),
            Contract::Outgoing(outgoing) => FundedContract::Outgoing(outgoing),
        }
    }
}

impl Encodable for ContractId {
    fn consensus_encode<W: std::io::Write>(&self, writer: W) -> Result<usize, Error> {
        self.as_inner().consensus_encode(writer)
    }
}

impl Decodable for ContractId {
    fn consensus_decode<D: std::io::Read>(d: D) -> Result<Self, DecodeError> {
        Ok(ContractId::from_inner(Decodable::consensus_decode(d)?))
    }
}
