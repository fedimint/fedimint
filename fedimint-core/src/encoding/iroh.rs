use std::io::{Error, Read, Write};

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

impl Encodable for iroh_base::SecretKey {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for iroh_base::SecretKey {
    fn consensus_decode_partial<D: Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::from_bytes(&<[u8; 32]>::consensus_decode_partial(
            d, modules,
        )?))
    }
}

impl Encodable for iroh_base::PublicKey {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.as_bytes().consensus_encode(writer)
    }
}

impl Decodable for iroh_base::PublicKey {
    fn consensus_decode_partial<D: Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::from_bytes(&<[u8; 32]>::consensus_decode_partial(d, modules)?)
            .map_err(DecodeError::from_err)
    }
}
