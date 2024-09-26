use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

impl Encodable for iroh_net::key::SecretKey {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for iroh_net::key::SecretKey {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::from_bytes(&<[u8; 32]>::consensus_decode(d, modules)?))
    }
}

impl Encodable for iroh_net::key::PublicKey {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.as_bytes().consensus_encode(writer)
    }
}

impl Decodable for iroh_net::key::PublicKey {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::from_bytes(&<[u8; 32]>::consensus_decode(d, modules)?).map_err(DecodeError::from_err)
    }
}
