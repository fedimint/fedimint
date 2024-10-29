use std::io::{Error, Write};
use std::str::FromStr;

use anyhow::format_err;
use bitcoin30::address::NetworkUnchecked;
use bitcoin30::hashes::Hash as BitcoinHash;
use hex::{FromHex, ToHex};
use miniscript::{Descriptor, MiniscriptKey};

use crate::bitcoin_migration::{
    bitcoin29_to_bitcoin30_psbt, bitcoin29_to_bitcoin32_network_magic, bitcoin30_to_bitcoin29_psbt,
    bitcoin30_to_bitcoin32_network, bitcoin32_to_bitcoin29_network_magic,
    bitcoin32_to_bitcoin30_network, checked_address_to_unchecked_address,
};
use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

// TODO(#5200): Remove this macro once the bitcoin v0.32 migration is complete.
macro_rules! impl_encode_decode_bridge_bitcoin30 {
    ($btc_type:ty) => {
        impl crate::encoding::Encodable for $btc_type {
            fn consensus_encode<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> Result<usize, std::io::Error> {
                bitcoin30::consensus::Encodable::consensus_encode(self, writer)
            }
        }

        impl crate::encoding::Decodable for $btc_type {
            fn consensus_decode_from_finite_reader<D: std::io::Read>(
                d: &mut D,
                _modules: &$crate::module::registry::ModuleDecoderRegistry,
            ) -> Result<Self, crate::encoding::DecodeError> {
                bitcoin30::consensus::Decodable::consensus_decode_from_finite_reader(d)
                    .map_err(crate::encoding::DecodeError::from_err)
            }
        }
    };
}

struct SimpleBitcoinRead<R: std::io::Read>(R);

impl<R: std::io::Read> bitcoin_io::Read for SimpleBitcoinRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> bitcoin_io::Result<usize> {
        self.0.read(buf).map_err(bitcoin_io::Error::from)
    }
}

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

impl_encode_decode_bridge_bitcoin30!(bitcoin30::block::Header);
impl_encode_decode_bridge_bitcoin30!(bitcoin30::BlockHash);
impl_encode_decode_bridge!(bitcoin::OutPoint);
impl_encode_decode_bridge_bitcoin30!(bitcoin30::ScriptBuf);
impl_encode_decode_bridge_bitcoin30!(bitcoin30::Transaction);
impl_encode_decode_bridge_bitcoin30!(bitcoin30::merkle_tree::PartialMerkleTree);

impl crate::encoding::Encodable for bitcoin30::psbt::PartiallySignedTransaction {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        bitcoin29::consensus::Encodable::consensus_encode(
            &bitcoin30_to_bitcoin29_psbt(self),
            writer,
        )
    }
}

impl crate::encoding::Decodable for bitcoin30::psbt::PartiallySignedTransaction {
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        Ok(bitcoin29_to_bitcoin30_psbt(
            &bitcoin29::consensus::Decodable::consensus_decode_from_finite_reader(d)
                .map_err(crate::encoding::DecodeError::from_err)?,
        ))
    }
}

impl crate::encoding::Encodable for bitcoin30::Txid {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        bitcoin30::consensus::Encodable::consensus_encode(self, writer)
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
impl crate::encoding::Decodable for bitcoin30::Txid {
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        _modules: &::fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        bitcoin30::consensus::Decodable::consensus_decode_from_finite_reader(d)
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

impl Encodable for bitcoin::p2p::Magic {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        // The encoding format for bitcoin v0.32 is different from bitcoin v0.29. We're
        // converting before encoding to maintain backwards compatibility.
        let num = bitcoin32_to_bitcoin29_network_magic(self);
        num.consensus_encode(writer)
    }
}

impl Decodable for bitcoin::p2p::Magic {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        // The encoding format for bitcoin v0.32 is different from bitcoin v0.29. We're
        // converting after decoding to maintain backwards compatibility.
        let num = u32::consensus_decode(d, modules)?;
        Ok(bitcoin29_to_bitcoin32_network_magic(num))
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
        let magic = bitcoin::p2p::Magic::consensus_decode(d, modules)?;
        Self::from_magic(magic).ok_or_else(|| {
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
        Ok(Self::from_sat(u64::consensus_decode(d, modules)?))
    }
}

impl Encodable for bitcoin30::Address {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += bitcoin30_to_bitcoin32_network(&self.network)
            .magic()
            .consensus_encode(writer)?;
        len += self.script_pubkey().consensus_encode(writer)?;
        Ok(len)
    }
}

impl Encodable for bitcoin30::Address<NetworkUnchecked> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.clone().assume_checked().consensus_encode(writer)
    }
}

impl Decodable for bitcoin30::Address<NetworkUnchecked> {
    fn consensus_decode<D: std::io::Read>(
        mut d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let network =
            bitcoin::Network::from_magic(bitcoin::p2p::Magic::consensus_decode(&mut d, modules)?)
                .ok_or_else(|| DecodeError::from_str("Unknown network"))?;
        let script_pk = bitcoin30::ScriptBuf::consensus_decode(&mut d, modules)?;

        let address =
            bitcoin30::Address::from_script(&script_pk, bitcoin32_to_bitcoin30_network(&network))
                .map_err(|e| DecodeError::new_custom(e.into()))?;

        Ok(checked_address_to_unchecked_address(&address))
    }
}

impl Encodable for bitcoin30::hashes::sha256::Hash {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_byte_array().consensus_encode(writer)
    }
}

impl Decodable for bitcoin30::hashes::sha256::Hash {
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

    use bitcoin30::hashes::Hash as BitcoinHash;

    use crate::encoding::{Decodable, Encodable};
    use crate::ModuleDecoderRegistry;

    #[test_log::test]
    fn sha256_roundtrip() {
        let hash = bitcoin30::hashes::sha256::Hash::hash(b"Hello world!");
        let mut encoded = Vec::new();
        hash.consensus_encode(&mut encoded).unwrap();
        let hash_decoded = bitcoin30::hashes::sha256::Hash::consensus_decode(
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
                bitcoin30::Address::from_str(address_str).expect("All tested addresses are valid");
            let mut encoding = vec![];
            address
                .consensus_encode(&mut encoding)
                .expect("Encoding to vec can't fail");
            let mut cursor = Cursor::new(encoding);
            let parsed_address = bitcoin30::Address::consensus_decode(
                &mut cursor,
                &ModuleDecoderRegistry::default(),
            )
            .expect("Decoding address failed");

            assert_eq!(address, parsed_address);
        }
    }
}
