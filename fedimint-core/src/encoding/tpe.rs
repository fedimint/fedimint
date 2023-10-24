use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use tpe::{CipherText, EphemeralPublicKey, EphemeralSignature};
macro_rules! impl_external_encode_bls {
    ($ext:ident $(:: $ext_path:ident)*, $group:ty, $byte_len:expr) => {
        impl $crate::encoding::Encodable for $ext $(:: $ext_path)* {
            fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
                let bytes = self.0.to_compressed();
                writer.write_all(&bytes)?;
                Ok(bytes.len())
            }
        }

        impl $crate::encoding::Decodable for $ext $(:: $ext_path)* {
            fn consensus_decode<D: std::io::Read>(
                d: &mut D,
                _modules: &$crate::module::registry::ModuleDecoderRegistry,
            ) -> Result<Self, crate::encoding::DecodeError> {
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

impl_external_encode_bls!(tpe::EphemeralPublicKey, tpe::G1Affine, 48);
impl_external_encode_bls!(tpe::DecryptionKeyShare, tpe::G1Affine, 48);
impl_external_encode_bls!(tpe::AggregateDecryptionKey, tpe::G1Affine, 48);
impl_external_encode_bls!(tpe::PublicKeyShare, tpe::G1Affine, 48);
impl_external_encode_bls!(tpe::AggregatePublicKey, tpe::G1Affine, 48);

impl_external_encode_bls!(tpe::EphemeralSignature, tpe::G2Affine, 96);

impl Encodable for CipherText {
    fn consensus_encode<W: std::io::Write>(&self, s: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;

        len += self.encrypted_preimage.consensus_encode(s)?;
        len += self.pk.consensus_encode(s)?;
        len += self.signature.consensus_encode(s)?;

        Ok(len)
    }
}

impl Decodable for CipherText {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(CipherText {
            encrypted_preimage: <[u8; 32]>::consensus_decode(d, modules)?,
            pk: EphemeralPublicKey::consensus_decode(d, modules)?,
            signature: EphemeralSignature::consensus_decode(d, modules)?,
        })
    }
}
