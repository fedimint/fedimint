use minimint_api::encoding::{Decodable, DecodeError, Encodable};
use std::io::Error;

/// Simplicity CMR
#[derive(Debug, Clone, Eq, PartialEq, Hash, Copy)]
pub struct ContractId(pub [u8; 32]);

impl Encodable for ContractId {
    fn consensus_encode<W: std::io::Write>(&self, writer: W) -> Result<usize, Error> {
        self.0.consensus_encode(writer)
    }
}

impl Decodable for ContractId {
    fn consensus_decode<D: std::io::Read>(d: D) -> Result<Self, DecodeError> {
        Ok(ContractId(Decodable::consensus_decode(d)?))
    }
}
