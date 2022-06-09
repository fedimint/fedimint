use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::Hash as BitcoinHash;
use bitcoin_hashes::{borrow_slice_impl, hash_newtype, hex_fmt_impl, index_impl, serde_impl};
use minimint_api::encoding::{Decodable, DecodeError, Encodable};
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
