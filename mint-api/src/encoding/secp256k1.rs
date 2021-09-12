use crate::encoding::{Decodable, DecodeError, Encodable};
use secp256k1::Signature;

impl Encodable for secp256k1::Signature {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let bytes = self.serialize_compact();
        writer.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for secp256k1::Signature {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 64];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Signature::from_compact(&bytes).map_err(DecodeError::from_err)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_roundtrip;
    use secp256k1::Message;

    #[test]
    fn test_sig() {
        let ctx = secp256k1::Secp256k1::new();
        let (sk, _pk) = ctx.generate_keypair(&mut rand::thread_rng());
        let sig = ctx.sign(
            &Message::from_hashed_data::<secp256k1::bitcoin_hashes::sha256::Hash>(b"Hello World!"),
            &sk,
        );

        test_roundtrip(sig);
    }
}
