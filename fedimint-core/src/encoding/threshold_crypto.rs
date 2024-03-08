use std::io::{Error, Read, Write};

use threshold_crypto::group::Curve;
use threshold_crypto::{G1Affine, G1Projective};

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

impl Encodable for threshold_crypto::PublicKeySet {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        let num_coeff = self.coefficients().len() as u64;
        len += num_coeff.consensus_encode(writer)?;
        for coefficient in self.coefficients() {
            len += coefficient
                .to_affine()
                .to_compressed()
                .consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl Decodable for threshold_crypto::PublicKeySet {
    fn consensus_decode<R: Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let num_coeff = u64::consensus_decode(r, modules)?;
        (0..num_coeff)
            .map(|_| {
                let bytes: [u8; 48] = Decodable::consensus_decode(r, modules)?;
                let point = G1Affine::from_compressed(&bytes);
                if point.is_some().unwrap_u8() == 1 {
                    let affine = point.unwrap();
                    Ok(G1Projective::from(affine))
                } else {
                    Err(crate::encoding::DecodeError::from_str(
                        "Error decoding public key",
                    ))
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|coefficients| {
                threshold_crypto::PublicKeySet::from(threshold_crypto::poly::Commitment::from(
                    coefficients,
                ))
            })
    }
}

impl Encodable for threshold_crypto::PublicKey {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for threshold_crypto::PublicKey {
    fn consensus_decode<R: Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes: [u8; 48] = Decodable::consensus_decode(r, modules)?;
        threshold_crypto::PublicKey::from_bytes(bytes).map_err(DecodeError::from_err)
    }
}

impl Encodable for threshold_crypto::Ciphertext {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for threshold_crypto::Ciphertext {
    fn consensus_decode<R: Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let ciphertext_bytes = Vec::<u8>::consensus_decode(reader, modules)?;
        threshold_crypto::Ciphertext::from_bytes(&ciphertext_bytes).ok_or_else(|| {
            DecodeError::from_str("Error decoding threshold_crypto::Ciphertext from bytes")
        })
    }
}

impl Encodable for threshold_crypto::DecryptionShare {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for threshold_crypto::DecryptionShare {
    fn consensus_decode<R: Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let decryption_share_bytes = <[u8; 48]>::consensus_decode(reader, modules)?;
        threshold_crypto::DecryptionShare::from_bytes(&decryption_share_bytes).ok_or_else(|| {
            DecodeError::from_str("Error decoding threshold_crypto::DecryptionShare from bytes")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_roundtrip;

    #[test_log::test]
    fn test_ciphertext() {
        let sks = threshold_crypto::SecretKeySet::random(1, &mut rand::thread_rng());
        let pks = sks.public_keys();
        let pk = pks.public_key();

        let message = b"Hello world!";
        let ciphertext = pk.encrypt(message);
        let decryption_share = sks.secret_key_share(0).decrypt_share(&ciphertext).unwrap();

        test_roundtrip(ciphertext);
        test_roundtrip(decryption_share);
    }
}
