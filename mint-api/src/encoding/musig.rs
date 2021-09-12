use crate::encoding::{Decodable, DecodeError, Encodable};
use tracing::trace;

impl Encodable for musig::PubKey {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let bytes = self.to_bytes();
        writer.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for musig::PubKey {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 33];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        musig::PubKey::from_bytes(bytes)
            .ok_or_else(|| DecodeError::from_str("Error deserializing fake musig pub key"))
    }
}

impl Encodable for musig::SecKey {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let bytes = self.to_bytes();
        writer.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for musig::SecKey {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 32];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        musig::SecKey::from_bytes(bytes)
            .ok_or_else(|| DecodeError::from_str("Error deserializing fake musig secret key"))
    }
}

impl Encodable for musig::Sig {
    fn consensus_encode<W: std::io::Write>(&self, writer: W) -> Result<usize, std::io::Error> {
        let bytes = self.to_bytes();
        trace!("Encoding musig::Sig as {:?}", bytes);
        Encodable::consensus_encode((&bytes) as &[u8; 65], writer)
    }
}

impl Decodable for musig::Sig {
    fn consensus_decode<D: std::io::Read>(d: D) -> Result<Self, DecodeError> {
        let bytes = <[u8; 65]>::consensus_decode(d)?;
        trace!("Decoding musig::Sig from {:?}", bytes);
        musig::Sig::from_bytes(bytes)
            .ok_or_else(|| DecodeError::from_str("Error deserializing fake musig signature"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_roundtrip;

    #[test]
    fn test_pub_key() {
        let mut rng = musig::rng_adapt::RngAdaptor(rand::rngs::OsRng::new().unwrap());
        let sec_key = musig::SecKey::random(&mut rng);
        let pub_key = sec_key.to_public();
        test_roundtrip(pub_key);

        let sig = musig::sign([0x42; 32], [sec_key].iter(), &mut rng);
        test_roundtrip(sig);
    }
}
