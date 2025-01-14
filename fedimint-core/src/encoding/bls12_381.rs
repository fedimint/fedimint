use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::Curve;

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

impl Encodable for Scalar {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for Scalar {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let byte_array = <[u8; 32]>::consensus_decode_partial(d, modules)?;

        Option::from(Self::from_bytes(&byte_array))
            .ok_or_else(|| DecodeError::from_str("Error decoding Scalar"))
    }
}

impl Encodable for G1Affine {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.to_compressed().consensus_encode(writer)
    }
}

impl Decodable for G1Affine {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let byte_array = <[u8; 48]>::consensus_decode_partial(d, modules)?;

        Option::from(Self::from_compressed(&byte_array))
            .ok_or_else(|| DecodeError::from_str("Error decoding G1Affine"))
    }
}

impl Encodable for G2Affine {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.to_compressed().consensus_encode(writer)
    }
}

impl Decodable for G2Affine {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let byte_array = <[u8; 96]>::consensus_decode_partial(d, modules)?;

        Option::from(Self::from_compressed(&byte_array))
            .ok_or_else(|| DecodeError::from_str("Error decoding G2Affine"))
    }
}

impl Encodable for G1Projective {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.to_affine().consensus_encode(writer)
    }
}

impl Decodable for G1Projective {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::from(G1Affine::consensus_decode_partial(d, modules)?))
    }
}

impl Encodable for G2Projective {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.to_affine().consensus_encode(writer)
    }
}

impl Decodable for G2Projective {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::from(G2Affine::consensus_decode_partial(d, modules)?))
    }
}
