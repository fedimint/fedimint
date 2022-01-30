use crate::encoding::{Decodable, DecodeError, Encodable};
use secp256k1_zkp::Signature;
use std::io::{Error, Read, Write};

impl Encodable for secp256k1_zkp::Signature {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let bytes = self.serialize_compact();
        writer.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for secp256k1_zkp::Signature {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 64];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Signature::from_compact(&bytes).map_err(DecodeError::from_err)
    }
}

impl Encodable for secp256k1_zkp::schnorrsig::PublicKey {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let bytes = self.serialize();
        writer.write_all(&bytes[..])?;
        Ok(bytes.len())
    }
}

impl Decodable for secp256k1_zkp::schnorrsig::PublicKey {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 32];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        secp256k1_zkp::schnorrsig::PublicKey::from_slice(&bytes[..]).map_err(DecodeError::from_err)
    }
}

impl Encodable for secp256k1_zkp::schnorrsig::Signature {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let bytes = &self[..];
        assert_eq!(
            bytes.len(),
            secp256k1_zkp::constants::SCHNORRSIG_SIGNATURE_SIZE
        );
        writer.write_all(bytes)?;
        Ok(secp256k1_zkp::constants::SCHNORRSIG_SIGNATURE_SIZE)
    }
}

impl Decodable for secp256k1_zkp::schnorrsig::Signature {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; secp256k1_zkp::constants::SCHNORRSIG_SIGNATURE_SIZE];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        secp256k1_zkp::schnorrsig::Signature::from_slice(&bytes).map_err(DecodeError::from_err)
    }
}

impl Encodable for secp256k1_zkp::schnorrsig::KeyPair {
    fn consensus_encode<W: Write>(&self, writer: W) -> Result<usize, Error> {
        self.serialize_secret().consensus_encode(writer)
    }
}

impl Decodable for secp256k1_zkp::schnorrsig::KeyPair {
    fn consensus_decode<D: Read>(d: D) -> Result<Self, DecodeError> {
        let sec_bytes = <[u8; 32]>::consensus_decode(d)?;
        Self::from_seckey_slice(secp256k1_zkp::global::SECP256K1, &sec_bytes) // FIXME: evaluate security risk of global ctx
            .map_err(DecodeError::from_err)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_roundtrip;
    use secp256k1_zkp::hashes::Hash as BitcoinHash;
    use secp256k1_zkp::Message;

    #[test]
    fn test_ecdsa_sig() {
        let ctx = secp256k1_zkp::Secp256k1::new();
        let (sk, _pk) = ctx.generate_keypair(&mut rand::thread_rng());
        let sig = ctx.sign(
            &Message::from_hashed_data::<secp256k1_zkp::hashes::sha256::Hash>(b"Hello World!"),
            &sk,
        );

        test_roundtrip(sig);
    }

    #[test]
    fn test_schnorr_pub_key() {
        let ctx = secp256k1_zkp::global::SECP256K1;
        let mut rng = rand::rngs::OsRng::new().unwrap();
        let sec_key = secp256k1_zkp::schnorrsig::KeyPair::new(&ctx, &mut rng);
        let pub_key = secp256k1_zkp::schnorrsig::PublicKey::from_keypair(&ctx, &sec_key);
        test_roundtrip(pub_key);

        let sig = ctx.schnorrsig_sign(
            &secp256k1_zkp::hashes::sha256::Hash::hash(b"Hello World!").into(),
            &sec_key,
        );

        test_roundtrip(sig);
    }
}
