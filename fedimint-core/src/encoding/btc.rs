use std::io::{Error, Write};
use std::str::FromStr;

use anyhow::format_err;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash as BitcoinHash;
use hex::{FromHex, ToHex};
use miniscript::{Descriptor, MiniscriptKey};
use serde::{Deserialize, Serialize};

use super::{BufBitcoinReader, CountWrite, SimpleBitcoinRead};
use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::get_network_for_address;
use crate::module::registry::ModuleDecoderRegistry;

macro_rules! impl_encode_decode_bridge {
    ($btc_type:ty) => {
        impl crate::encoding::Encodable for $btc_type {
            fn consensus_encode<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> Result<usize, std::io::Error> {
                Ok(bitcoin::consensus::Encodable::consensus_encode(
                    self,
                    &mut std::io::BufWriter::new(writer),
                )?)
            }
        }

        impl crate::encoding::Decodable for $btc_type {
            fn consensus_decode_from_finite_reader<D: std::io::Read>(
                d: &mut D,
                _modules: &$crate::module::registry::ModuleDecoderRegistry,
            ) -> Result<Self, crate::encoding::DecodeError> {
                bitcoin::consensus::Decodable::consensus_decode_from_finite_reader(
                    &mut SimpleBitcoinRead(d),
                )
                .map_err(crate::encoding::DecodeError::from_err)
            }
        }
    };
}

impl_encode_decode_bridge!(bitcoin::block::Header);
impl_encode_decode_bridge!(bitcoin::BlockHash);
impl_encode_decode_bridge!(bitcoin::OutPoint);
impl_encode_decode_bridge!(bitcoin::ScriptBuf);
impl_encode_decode_bridge!(bitcoin::Transaction);
impl_encode_decode_bridge!(bitcoin::merkle_tree::PartialMerkleTree);

impl crate::encoding::Encodable for bitcoin::psbt::Psbt {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        Ok(self.serialize_to_writer(&mut CountWrite::from(writer))?)
    }
}

impl crate::encoding::Decodable for bitcoin::psbt::Psbt {
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        Self::deserialize_from_reader(&mut BufBitcoinReader::new(d))
            .map_err(crate::encoding::DecodeError::from_err)
    }
}

impl crate::encoding::Encodable for bitcoin::Txid {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        Ok(bitcoin::consensus::Encodable::consensus_encode(
            self,
            &mut std::io::BufWriter::new(writer),
        )?)
    }

    fn consensus_encode_to_hex(&self) -> String {
        let mut bytes = vec![];
        self.consensus_encode(&mut bytes)
            .expect("encoding to bytes can't fail for io reasons");

        // Just Bitcoin things: transaction hashes are encoded reverse
        bytes.reverse();

        // TODO: remove double-allocation
        bytes.encode_hex()
    }
}

impl crate::encoding::Decodable for bitcoin::Txid {
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        _modules: &::fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        bitcoin::consensus::Decodable::consensus_decode_from_finite_reader(&mut SimpleBitcoinRead(
            d,
        ))
        .map_err(crate::encoding::DecodeError::from_err)
    }

    fn consensus_decode_hex(
        hex: &str,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = Vec::<u8>::from_hex(hex)
            .map_err(anyhow::Error::from)
            .map_err(DecodeError::new_custom)?;

        // Just Bitcoin things: transaction hashes are encoded reverse
        bytes.reverse();

        let mut reader = std::io::Cursor::new(bytes);
        Decodable::consensus_decode(&mut reader, modules)
    }
}

impl<K> Encodable for Descriptor<K>
where
    K: MiniscriptKey,
{
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let descriptor_str = self.to_string();
        descriptor_str.consensus_encode(writer)
    }
}

impl<K> Decodable for Descriptor<K>
where
    Self: FromStr,
    <Self as FromStr>::Err: ToString + std::error::Error + Send + Sync + 'static,
    K: MiniscriptKey,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let descriptor_str = String::consensus_decode_from_finite_reader(d, modules)?;
        Self::from_str(&descriptor_str).map_err(DecodeError::from_err)
    }
}

impl Encodable for bitcoin::Network {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        u32::from_le_bytes(self.magic().to_bytes()).consensus_encode(writer)
    }
}

impl Decodable for bitcoin::Network {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let num = u32::consensus_decode(d, modules)?;
        let magic = bitcoin::p2p::Magic::from_bytes(num.to_le_bytes());
        Self::from_magic(magic).ok_or_else(|| {
            DecodeError::new_custom(format_err!("Unknown network magic: {:x}", magic))
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct NetworkSaneEncodingWrapper(pub bitcoin::Network);

impl Encodable for NetworkSaneEncodingWrapper {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.0.magic().to_bytes().consensus_encode(writer)
    }
}

impl Decodable for NetworkSaneEncodingWrapper {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self(
            bitcoin::Network::from_magic(bitcoin::p2p::Magic::from_bytes(
                Decodable::consensus_decode(d, modules)?,
            ))
            .ok_or_else(|| DecodeError::new_custom(format_err!("Unknown network magic")))?,
        ))
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
        Ok(Self::from_sat(u64::consensus_decode(d, modules)?))
    }
}

impl Encodable for bitcoin::Address<NetworkUnchecked> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += get_network_for_address(self.as_unchecked()).consensus_encode(writer)?;
        len += self
            .clone()
            .assume_checked()
            .script_pubkey()
            .consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for bitcoin::Address<NetworkUnchecked> {
    fn consensus_decode<D: std::io::Read>(
        mut d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let network = bitcoin::Network::consensus_decode(&mut d, modules)?;
        let script_pk = bitcoin::ScriptBuf::consensus_decode(&mut d, modules)?;

        let address = bitcoin::Address::from_script(&script_pk, network)
            .map_err(|e| DecodeError::new_custom(e.into()))?;

        Ok(address.as_unchecked().clone())
    }
}

impl Encodable for bitcoin::hashes::sha256::Hash {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_byte_array().consensus_encode(writer)
    }
}

impl Decodable for bitcoin::hashes::sha256::Hash {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::from_byte_array(Decodable::consensus_decode(
            d, modules,
        )?))
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
    fn network_roundtrip() {
        let networks: [(bitcoin::Network, [u8; 5]); 5] = [
            (bitcoin::Network::Bitcoin, [0xFE, 0xD9, 0xB4, 0xBE, 0xF9]),
            (bitcoin::Network::Testnet, [0xFE, 0x07, 0x09, 0x11, 0x0B]),
            (bitcoin::Network::Testnet4, [0xFE, 0x28, 0x3F, 0x16, 0x1C]),
            (bitcoin::Network::Signet, [0xFE, 0x40, 0xCF, 0x03, 0x0A]),
            (bitcoin::Network::Regtest, [0xFE, 0xDA, 0xB5, 0xBF, 0xFA]),
        ];

        for (network, magic_bytes) in networks {
            let mut network_encoded = Vec::new();
            network.consensus_encode(&mut network_encoded).unwrap();

            let network_decoded = bitcoin::Network::consensus_decode(
                &mut Cursor::new(network_encoded.clone()),
                &ModuleDecoderRegistry::default(),
            )
            .unwrap();

            assert_eq!(magic_bytes, *network_encoded);
            assert_eq!(network, network_decoded);
        }
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
}
