use bls12_381::{G1Affine, G2Affine, Scalar};

use crate::encoding::{Decodable, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

impl Encodable for Scalar {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for Scalar {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        let mut bytes = [0u8; 32];

        d.read_exact(&mut bytes)
            .map_err(crate::encoding::DecodeError::from_err)?;

        let scalar = Scalar::from_bytes(&bytes);

        if scalar.is_some().unwrap_u8() == 1 {
            Ok(scalar.unwrap())
        } else {
            Err(crate::encoding::DecodeError::from_str(
                "Error decoding Scalar",
            ))
        }
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
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        let mut bytes = [0u8; 48];

        d.read_exact(&mut bytes)
            .map_err(crate::encoding::DecodeError::from_err)?;

        let point = G1Affine::from_compressed(&bytes);

        if point.is_some().unwrap_u8() == 1 {
            Ok(point.unwrap())
        } else {
            Err(crate::encoding::DecodeError::from_str(
                "Error decoding compressed G1Affine",
            ))
        }
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
        _modules: &crate::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        let mut bytes = [0u8; 96];

        d.read_exact(&mut bytes)
            .map_err(crate::encoding::DecodeError::from_err)?;

        let point = G2Affine::from_compressed(&bytes);

        if point.is_some().unwrap_u8() == 1 {
            Ok(point.unwrap())
        } else {
            Err(crate::encoding::DecodeError::from_str(
                "Error decoding compressed G2Affine",
            ))
        }
    }
}
