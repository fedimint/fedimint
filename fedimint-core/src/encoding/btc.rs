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

/// Wrapper around `bitcoin::Network` that encodes and decodes the network as a
/// little-endian u32. This is here for backwards compatibility and is used by
/// the LNv1 and WalletV1 modules.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct NetworkLegacyEncodingWrapper(pub bitcoin::Network);

impl std::fmt::Display for NetworkLegacyEncodingWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Encodable for NetworkLegacyEncodingWrapper {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        u32::from_le_bytes(self.0.magic().to_bytes()).consensus_encode(writer)
    }
}

impl Decodable for NetworkLegacyEncodingWrapper {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let num = u32::consensus_decode(d, modules)?;
        let magic = bitcoin::p2p::Magic::from_bytes(num.to_le_bytes());
        let network = bitcoin::Network::from_magic(magic).ok_or_else(|| {
            DecodeError::new_custom(format_err!("Unknown network magic: {:x}", magic))
        })?;
        Ok(Self(network))
    }
}
impl Encodable for bitcoin::Network {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.magic().to_bytes().consensus_encode(writer)
    }
}

impl Decodable for bitcoin::Network {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::from_magic(bitcoin::p2p::Magic::from_bytes(
            Decodable::consensus_decode(d, modules)?,
        ))
        .ok_or_else(|| DecodeError::new_custom(format_err!("Unknown network magic")))
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
        len += NetworkLegacyEncodingWrapper(get_network_for_address(self.as_unchecked()))
            .consensus_encode(writer)?;
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
        let network = NetworkLegacyEncodingWrapper::consensus_decode(&mut d, modules)?.0;
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

    use crate::encoding::btc::NetworkLegacyEncodingWrapper;
    use crate::encoding::tests::test_roundtrip_expected;
    use crate::encoding::{Decodable, Encodable};
    use crate::ModuleDecoderRegistry;

    #[test_log::test]
    fn network_roundtrip() {
        let networks: [(bitcoin::Network, [u8; 5], [u8; 4]); 5] = [
            (
                bitcoin::Network::Bitcoin,
                [0xFE, 0xD9, 0xB4, 0xBE, 0xF9],
                [0xF9, 0xBE, 0xB4, 0xD9],
            ),
            (
                bitcoin::Network::Testnet,
                [0xFE, 0x07, 0x09, 0x11, 0x0B],
                [0x0B, 0x11, 0x09, 0x07],
            ),
            (
                bitcoin::Network::Testnet4,
                [0xFE, 0x28, 0x3F, 0x16, 0x1C],
                [0x1C, 0x16, 0x3F, 0x28],
            ),
            (
                bitcoin::Network::Signet,
                [0xFE, 0x40, 0xCF, 0x03, 0x0A],
                [0x0A, 0x03, 0xCF, 0x40],
            ),
            (
                bitcoin::Network::Regtest,
                [0xFE, 0xDA, 0xB5, 0xBF, 0xFA],
                [0xFA, 0xBF, 0xB5, 0xDA],
            ),
        ];

        for (network, magic_legacy_bytes, magic_bytes) in networks {
            let mut network_legacy_encoded = Vec::new();
            NetworkLegacyEncodingWrapper(network)
                .consensus_encode(&mut network_legacy_encoded)
                .unwrap();

            let mut network_encoded = Vec::new();
            network.consensus_encode(&mut network_encoded).unwrap();

            let network_legacy_decoded = NetworkLegacyEncodingWrapper::consensus_decode(
                &mut Cursor::new(network_legacy_encoded.clone()),
                &ModuleDecoderRegistry::default(),
            )
            .unwrap()
            .0;

            let network_decoded = bitcoin::Network::consensus_decode(
                &mut Cursor::new(network_encoded.clone()),
                &ModuleDecoderRegistry::default(),
            )
            .unwrap();

            assert_eq!(magic_legacy_bytes, *network_legacy_encoded);
            assert_eq!(magic_bytes, *network_encoded);
            assert_eq!(network, network_legacy_decoded);
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
        test_roundtrip_expected(
            &bitcoin::hashes::sha256::Hash::hash(b"Hello world!"),
            &[
                192, 83, 94, 75, 226, 183, 159, 253, 147, 41, 19, 5, 67, 107, 248, 137, 49, 78, 74,
                63, 174, 192, 94, 207, 252, 187, 125, 243, 26, 217, 229, 26,
            ],
        );
    }
}
