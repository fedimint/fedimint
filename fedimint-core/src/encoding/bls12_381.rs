use bls12_381::{G1Affine, G2Affine, Scalar};

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

impl Encodable for Scalar {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for Scalar {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let byte_array = <[u8; 32]>::consensus_decode(d, modules)?;

        Option::from(Scalar::from_bytes(&byte_array))
            .ok_or(DecodeError::from_str("Error decoding Scalar"))
    }
}

impl Encodable for G1Affine {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.to_compressed().consensus_encode(writer)
    }
}

impl Decodable for G1Affine {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let byte_array = <[u8; 48]>::consensus_decode(d, modules)?;

        Option::from(G1Affine::from_compressed(&byte_array))
            .ok_or(DecodeError::from_str("Error decoding G1Affine"))
    }
}

impl Encodable for G2Affine {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.to_compressed().consensus_encode(writer)
    }
}

impl Decodable for G2Affine {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let byte_array = <[u8; 96]>::consensus_decode(d, modules)?;

        Option::from(G2Affine::from_compressed(&byte_array))
            .ok_or(DecodeError::from_str("Error decoding G2Affine"))
    }
}
