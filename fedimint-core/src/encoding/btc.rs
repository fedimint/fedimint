use std::io::{Error, Write};
use std::str::FromStr;

use anyhow::format_err;
use bitcoin::hashes::Hash as BitcoinHash;
use miniscript::{Descriptor, MiniscriptKey};

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

macro_rules! impl_encode_decode_bridge {
    ($btc_type:ty) => {
        impl crate::encoding::Encodable for $btc_type {
            fn consensus_encode<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> Result<usize, std::io::Error> {
                bitcoin::consensus::Encodable::consensus_encode(self, writer)
            }
        }

        impl crate::encoding::Decodable for $btc_type {
            fn consensus_decode<D: std::io::Read>(
                d: &mut D,
                _modules: &$crate::module::registry::ModuleDecoderRegistry,
            ) -> Result<Self, crate::encoding::DecodeError> {
                bitcoin::consensus::Decodable::consensus_decode(d)
                    .map_err(crate::encoding::DecodeError::from_err)
            }
        }
    };
}

impl_encode_decode_bridge!(bitcoin::BlockHeader);
impl_encode_decode_bridge!(bitcoin::BlockHash);
impl_encode_decode_bridge!(bitcoin::OutPoint);
impl_encode_decode_bridge!(bitcoin::Script);
impl_encode_decode_bridge!(bitcoin::Transaction);
impl_encode_decode_bridge!(bitcoin::Txid);
impl_encode_decode_bridge!(bitcoin::util::merkleblock::PartialMerkleTree);
impl_encode_decode_bridge!(bitcoin::util::psbt::PartiallySignedTransaction);

impl<K> Encodable for miniscript::Descriptor<K>
where
    K: miniscript::MiniscriptKey,
{
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let descriptor_str = self.to_string();
        descriptor_str.consensus_encode(writer)
    }
}

impl<K> Decodable for miniscript::Descriptor<K>
where
    Self: FromStr,
    <Self as FromStr>::Err: ToString + std::error::Error + Send + Sync + 'static,
    K: MiniscriptKey,
{
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let descriptor_str = String::consensus_decode(d, modules)?;
        Descriptor::<K>::from_str(&descriptor_str).map_err(DecodeError::from_err)
    }
}

impl Encodable for bitcoin::Network {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.magic().consensus_encode(writer)
    }
}

impl Decodable for bitcoin::Network {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let magic = u32::consensus_decode(d, modules)?;
        bitcoin::Network::from_magic(magic).ok_or_else(|| {
            DecodeError::new_custom(format_err!("Unknown network magic: {:x}", magic))
        })
    }
}

impl Encodable for bitcoin::Amount {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.to_sat().consensus_encode(writer)
    }
}

impl Decodable for bitcoin::Amount {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(bitcoin::Amount::from_sat(u64::consensus_decode(
            d, modules,
        )?))
    }
}

impl Encodable for bitcoin::Address {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.network.magic().consensus_encode(writer)?;
        len += self.script_pubkey().consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for bitcoin::Address {
    fn consensus_decode<D: std::io::Read>(
        mut d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let network = bitcoin::Network::from_magic(u32::consensus_decode(&mut d, modules)?)
            .ok_or_else(|| DecodeError::from_str("Unknown network"))?;
        let script_pk = bitcoin::Script::consensus_decode(&mut d, modules)?;

        bitcoin::Address::from_script(&script_pk, network)
            .map_err(|e| DecodeError::new_custom(e.into()))
    }
}

impl Encodable for bitcoin::hashes::sha256::Hash {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.into_inner().consensus_encode(writer)
    }
}

impl Decodable for bitcoin::hashes::sha256::Hash {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(bitcoin::hashes::sha256::Hash::from_inner(
            Decodable::consensus_decode(d, modules)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::str::FromStr;

    use bitcoin::hashes::Hash as BitcoinHash;

    use crate::encoding::{Decodable, Encodable};
    use crate::ModuleDecoderRegistry;

    #[test_log::test]
    fn sha256_roundtrip() {
        let hash = bitcoin::hashes::sha256::Hash::hash(b"Hello world!");
        let mut encoded = Vec::new();
        hash.consensus_encode(&mut encoded).unwrap();
        let hash_decoded = bitcoin::hashes::sha256::Hash::consensus_decode(
            &mut Cursor::new(encoded),
            &ModuleDecoderRegistry::default(),
        )
        .unwrap();
        assert_eq!(hash, hash_decoded);
    }

    #[test_log::test]
    fn address_roundtrip() {
        let addresses = [
            "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5",
            "mxMYaq5yWinZ9AKjCDcBEbiEwPJD9n2uLU",
            "1FK8o7mUxyd6QWJAUw7J4vW7eRxuyjj6Ne",
            "3JSrSU7z7R1Yhh26pt1zzRjQz44qjcrXwb",
            "tb1qunn0thpt8uk3yk2938ypjccn3urxprt78z9ccq",
            "2MvUMRv2DRHZi3VshkP7RMEU84mVTfR9xjq",
        ];

        for address_str in addresses {
            let address =
                bitcoin::Address::from_str(address_str).expect("All tested addresses are valid");
            let mut encoding = vec![];
            address
                .consensus_encode(&mut encoding)
                .expect("Encoding to vec can't fail");
            let mut cursor = Cursor::new(encoding);
            let parsed_address =
                bitcoin::Address::consensus_decode(&mut cursor, &ModuleDecoderRegistry::default())
                    .expect("Decoding address failed");

            assert_eq!(address, parsed_address);
        }
    }
}
