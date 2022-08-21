use crate::encoding::{Decodable, DecodeError, Encodable};

macro_rules! impl_external_encode_bls {
    ($ext:ident $(:: $ext_path:ident)*, $group:ty, $byte_len:expr) => {
        impl crate::encoding::Encodable for $ext $(:: $ext_path)* {
            fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
                let bytes = self.0.to_compressed();
                writer.write_all(&bytes)?;
                Ok(bytes.len())
            }
        }

        impl crate::encoding::Decodable for $ext $(:: $ext_path)* {
            fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, crate::encoding::DecodeError> {
                let mut bytes = [0u8; $byte_len];
                d.read_exact(&mut bytes).map_err(crate::encoding::DecodeError::from_err)?;
                let msg = <$group>::from_compressed(&bytes);

                if msg.is_some().unwrap_u8() == 1 {
                    Ok($ext $(:: $ext_path)*(msg.unwrap()))
                } else {
                    Err(crate::encoding::DecodeError::from_str("Error decoding blind message"))
                }
            }
        }
    };
}

impl_external_encode_bls!(tbs::BlindedMessage, tbs::MessagePoint, 48);
impl_external_encode_bls!(tbs::BlindedSignatureShare, tbs::MessagePoint, 48);
impl_external_encode_bls!(tbs::BlindedSignature, tbs::MessagePoint, 48);
impl_external_encode_bls!(tbs::Signature, tbs::MessagePoint, 48);

impl Encodable for tbs::BlindingKey {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        writer.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for tbs::BlindingKey {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 32];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        let key = tbs::Scalar::from_bytes(&bytes);

        if key.is_some().unwrap_u8() == 1 {
            Ok(tbs::BlindingKey(key.unwrap()))
        } else {
            Err(crate::encoding::DecodeError::from_str(
                "Error decoding blinding key",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_roundtrip;
    use tbs::{BlindedMessage, BlindingKey};

    #[test_log::test]
    fn test_message_macro() {
        let bmsg = BlindedMessage(tbs::MessagePoint::generator());
        test_roundtrip(bmsg);
    }

    #[test_log::test]
    fn test_bkey() {
        let bkey = BlindingKey::random();
        test_roundtrip(bkey);
    }
}
