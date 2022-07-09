use crate::encoding::{Decodable, DecodeError, Encodable};
use bitcoin::secp256k1::{
    constants,
    ecdsa::{self, Signature},
    global, schnorr, XOnlyPublicKey,
};

use std::io::{Error, Read, Write};

impl Encodable for ecdsa::Signature {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let bytes = self.serialize_compact();
        writer.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for ecdsa::Signature {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 64];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Signature::from_compact(&bytes).map_err(DecodeError::from_err)
    }
}

impl Encodable for XOnlyPublicKey {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let bytes = self.serialize();
        writer.write_all(&bytes[..])?;
        Ok(bytes.len())
    }
}

impl Decodable for XOnlyPublicKey {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 32];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        XOnlyPublicKey::from_slice(&bytes[..]).map_err(DecodeError::from_err)
    }
}

impl Encodable for schnorr::Signature {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let bytes = &self[..];
        assert_eq!(bytes.len(), constants::SCHNORR_SIGNATURE_SIZE);
        writer.write_all(bytes)?;
        Ok(constants::SCHNORR_SIGNATURE_SIZE)
    }
}

impl Decodable for schnorr::Signature {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; constants::SCHNORR_SIGNATURE_SIZE];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        schnorr::Signature::from_slice(&bytes).map_err(DecodeError::from_err)
    }
}

impl Encodable for bitcoin::KeyPair {
    fn consensus_encode<W: Write>(&self, writer: W) -> Result<usize, Error> {
        self.secret_bytes().consensus_encode(writer)
    }
}

impl Decodable for bitcoin::KeyPair {
    fn consensus_decode<D: Read>(d: D) -> Result<Self, DecodeError> {
        let sec_bytes = <[u8; 32]>::consensus_decode(d)?;
        Self::from_seckey_slice(global::SECP256K1, &sec_bytes) // FIXME: evaluate security risk of global ctx
            .map_err(DecodeError::from_err)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_roundtrip;
    use bitcoin::secp256k1::{global, Message, Secp256k1};
    use bitcoin_hashes::{sha256, Hash};
    use rand::rngs::OsRng;

    #[test_log::test]
    fn test_ecdsa_sig() {
        let ctx = Secp256k1::new();
        let (sk, _pk) = ctx.generate_keypair(&mut rand::thread_rng());
        let sig = ctx.sign_ecdsa(
            &Message::from_hashed_data::<sha256::Hash>(b"Hello World!"),
            &sk,
        );

        test_roundtrip(sig);
    }

    #[test_log::test]
    fn test_schnorr_pub_key() {
        let ctx = global::SECP256K1;
        let mut rng = OsRng::new().unwrap();
        let sec_key = bitcoin::KeyPair::new(ctx, &mut rng);
        let pub_key = sec_key.public_key();
        test_roundtrip(pub_key);

        let sig = ctx.sign_schnorr(&sha256::Hash::hash(b"Hello World!").into(), &sec_key);

        test_roundtrip(sig);
    }
}
