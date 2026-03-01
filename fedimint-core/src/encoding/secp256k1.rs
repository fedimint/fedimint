use std::io::{Error, Read, Write};

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

impl Encodable for secp256k1::ecdsa::Signature {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = self.serialize_compact();
        writer.write_all(&bytes)?;
        Ok(())
    }
}

impl Decodable for secp256k1::ecdsa::Signature {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::from_compact(&<[u8; 64]>::consensus_decode_partial(d, modules)?)
            .map_err(DecodeError::from_err)
    }
}

impl Encodable for secp256k1::PublicKey {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.serialize().consensus_encode(writer)
    }
}

impl Decodable for secp256k1::PublicKey {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::from_slice(&<[u8; 33]>::consensus_decode_partial(d, modules)?)
            .map_err(DecodeError::from_err)
    }
}

impl Encodable for secp256k1::XOnlyPublicKey {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.serialize().consensus_encode(writer)
    }
}

impl Decodable for secp256k1::XOnlyPublicKey {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::from_slice(&<[u8; 32]>::consensus_decode_partial(d, modules)?)
            .map_err(DecodeError::from_err)
    }
}

impl Encodable for secp256k1::SecretKey {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.secret_bytes().consensus_encode(writer)
    }
}

impl Decodable for secp256k1::SecretKey {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::from_slice(&<[u8; 32]>::consensus_decode_partial(d, modules)?)
            .map_err(DecodeError::from_err)
    }
}

impl Encodable for secp256k1::schnorr::Signature {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = &self[..];
        assert_eq!(bytes.len(), secp256k1::constants::SCHNORR_SIGNATURE_SIZE);
        writer.write_all(bytes)?;
        Ok(())
    }
}

impl Decodable for secp256k1::schnorr::Signature {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = <[u8; secp256k1::constants::SCHNORR_SIGNATURE_SIZE]>::consensus_decode_partial(
            d, modules,
        )?;
        Self::from_slice(&bytes).map_err(DecodeError::from_err)
    }
}

impl Encodable for bitcoin::key::Keypair {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.secret_bytes().consensus_encode(writer)
    }
}

impl Decodable for bitcoin::key::Keypair {
    fn consensus_decode_partial<D: Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let sec_bytes = <[u8; 32]>::consensus_decode_partial(d, modules)?;
        Self::from_seckey_slice(bitcoin::secp256k1::global::SECP256K1, &sec_bytes) // FIXME: evaluate security risk of global ctx
            .map_err(DecodeError::from_err)
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::Message;
    use secp256k1::hashes::Hash as BitcoinHash;

    use super::super::tests::test_roundtrip;

    #[test_log::test]
    fn test_ecdsa_sig() {
        let ctx = secp256k1::Secp256k1::new();
        let (sk, _pk) = ctx.generate_keypair(&mut rand::thread_rng());
        let sig = ctx.sign_ecdsa(
            &Message::from_digest(*secp256k1::hashes::sha256::Hash::hash(b"Hello World!").as_ref()),
            &sk,
        );

        test_roundtrip(&sig);
    }

    #[test_log::test]
    fn test_schnorr_pub_key() {
        let ctx = secp256k1::global::SECP256K1;
        let mut rng = rand::rngs::OsRng;
        let sec_key = bitcoin::key::Keypair::new(ctx, &mut rng);
        let pub_key = sec_key.public_key();
        test_roundtrip(&pub_key);

        let sig = ctx.sign_schnorr(
            &Message::from_digest(*secp256k1::hashes::sha256::Hash::hash(b"Hello World!").as_ref()),
            &sec_key,
        );

        test_roundtrip(&sig);
    }
}
