use std::io::{Error, Write};
use std::str::FromStr;

use anyhow::format_err;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash as BitcoinHash;
use hex::{FromHex, ToHex};
use lightning::util::ser::{BigSize, Readable, Writeable};
use miniscript::{Descriptor, MiniscriptKey};
use serde::{Deserialize, Serialize};

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::get_network_for_address;
use crate::module::registry::ModuleDecoderRegistry;

macro_rules! impl_encode_decode_bridge {
    ($btc_type:ty) => {
        impl crate::encoding::Encodable for $btc_type {
            fn consensus_encode<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> Result<(), std::io::Error> {
                bitcoin::consensus::Encodable::consensus_encode(
                    self,
                    &mut std::io::BufWriter::new(writer),
                )?;
                Ok(())
            }
        }

        impl crate::encoding::Decodable for $btc_type {
            fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
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
impl_encode_decode_bridge!(bitcoin::TxOut);
impl_encode_decode_bridge!(bitcoin::ScriptBuf);
impl_encode_decode_bridge!(bitcoin::Transaction);
impl_encode_decode_bridge!(bitcoin::merkle_tree::PartialMerkleTree);

impl crate::encoding::Encodable for bitcoin::psbt::Psbt {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.serialize_to_writer(&mut BitoinIoWriteAdapter::from(writer))?;
        Ok(())
    }
}

impl crate::encoding::Decodable for bitcoin::psbt::Psbt {
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        Self::deserialize_from_reader(&mut BufBitcoinReader::new(d))
            .map_err(crate::encoding::DecodeError::from_err)
    }
}

impl crate::encoding::Encodable for bitcoin::Txid {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        bitcoin::consensus::Encodable::consensus_encode(
            self,
            &mut std::io::BufWriter::new(writer),
        )?;
        Ok(())
    }

    fn consensus_encode_to_hex(&self) -> String {
        let mut bytes = self.consensus_encode_to_vec();

        // Just Bitcoin things: transaction hashes are encoded reverse
        bytes.reverse();

        // TODO: remove double-allocation
        bytes.encode_hex()
    }
}

impl crate::encoding::Decodable for bitcoin::Txid {
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
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

        Decodable::consensus_decode_whole(&bytes, modules)
    }
}

impl<K> Encodable for Descriptor<K>
where
    K: MiniscriptKey,
{
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
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
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let descriptor_str = String::consensus_decode_partial_from_finite_reader(d, modules)?;
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
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        u32::from_le_bytes(self.0.magic().to_bytes()).consensus_encode(writer)
    }
}

impl Decodable for NetworkLegacyEncodingWrapper {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let num = u32::consensus_decode_partial(d, modules)?;
        let magic = bitcoin::p2p::Magic::from_bytes(num.to_le_bytes());
        let network = bitcoin::Network::from_magic(magic).ok_or_else(|| {
            DecodeError::new_custom(format_err!("Unknown network magic: {:x}", magic))
        })?;
        Ok(Self(network))
    }
}
impl Encodable for bitcoin::Network {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.magic().to_bytes().consensus_encode(writer)
    }
}

impl Decodable for bitcoin::Network {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::from_magic(bitcoin::p2p::Magic::from_bytes(
            Decodable::consensus_decode_partial(d, modules)?,
        ))
        .ok_or_else(|| DecodeError::new_custom(format_err!("Unknown network magic")))
    }
}

impl Encodable for bitcoin::Amount {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.to_sat().consensus_encode(writer)
    }
}

impl Decodable for bitcoin::Amount {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::from_sat(u64::consensus_decode_partial(d, modules)?))
    }
}

impl Encodable for bitcoin::Address<NetworkUnchecked> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        NetworkLegacyEncodingWrapper(get_network_for_address(self)).consensus_encode(writer)?;
        self.clone()
            // We need an `Address<NetworkChecked>` in order to get the script pubkey.
            // Calling `assume_checked` is generally a bad idea, but it's safe here where we're
            // encoding the address because addresses are always decoded as unchecked.
            .assume_checked()
            .script_pubkey()
            .consensus_encode(writer)?;
        Ok(())
    }
}

impl Decodable for bitcoin::Address<NetworkUnchecked> {
    fn consensus_decode_partial<D: std::io::Read>(
        mut d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let network = NetworkLegacyEncodingWrapper::consensus_decode_partial(&mut d, modules)?.0;
        let script_pk = bitcoin::ScriptBuf::consensus_decode_partial(&mut d, modules)?;

        let address = bitcoin::Address::from_script(&script_pk, network)
            .map_err(|e| DecodeError::new_custom(e.into()))?;

        Ok(address.into_unchecked())
    }
}

impl Encodable for bitcoin::hashes::sha256::Hash {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.to_byte_array().consensus_encode(writer)
    }
}

impl Decodable for bitcoin::hashes::sha256::Hash {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::from_byte_array(Decodable::consensus_decode_partial(
            d, modules,
        )?))
    }
}

impl Encodable for bitcoin::hashes::hash160::Hash {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.to_byte_array().consensus_encode(writer)
    }
}

impl Decodable for bitcoin::hashes::hash160::Hash {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::from_byte_array(Decodable::consensus_decode_partial(
            d, modules,
        )?))
    }
}

impl Encodable for lightning_invoice::Bolt11Invoice {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.to_string().consensus_encode(writer)
    }
}

impl Decodable for lightning_invoice::Bolt11Invoice {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        String::consensus_decode_partial(d, modules)?
            .parse::<Self>()
            .map_err(DecodeError::from_err)
    }
}

impl Encodable for lightning_invoice::RoutingFees {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.base_msat.consensus_encode(writer)?;
        self.proportional_millionths.consensus_encode(writer)?;
        Ok(())
    }
}

impl Decodable for lightning_invoice::RoutingFees {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let base_msat = Decodable::consensus_decode_partial(d, modules)?;
        let proportional_millionths = Decodable::consensus_decode_partial(d, modules)?;
        Ok(Self {
            base_msat,
            proportional_millionths,
        })
    }
}

impl Encodable for BigSize {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let mut writer = BitoinIoWriteAdapter::from(writer);
        self.write(&mut writer)?;
        Ok(())
    }
}

impl Decodable for BigSize {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::read(&mut SimpleBitcoinRead(r))
            .map_err(|e| DecodeError::new_custom(anyhow::anyhow!("BigSize decoding error: {e:?}")))
    }
}

// Simple decoder implementing `bitcoin_io::Read` for `std::io::Read`.
// This is needed because `bitcoin::consensus::Decodable` requires a
// `bitcoin_io::Read`.
struct SimpleBitcoinRead<R: std::io::Read>(R);

impl<R: std::io::Read> bitcoin_io::Read for SimpleBitcoinRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> bitcoin_io::Result<usize> {
        self.0.read(buf).map_err(bitcoin_io::Error::from)
    }
}

/// Wrap buffering support for implementations of Read.
/// A reader which keeps an internal buffer to avoid hitting the underlying
/// stream directly for every read.
///
/// In order to avoid reading bytes past the first object, and those bytes then
/// ending up getting dropped, this BufBitcoinReader operates in
/// one-byte-increments.
///
/// This code is vendored from the `lightning` crate:
/// <https://github.com/lightningdevkit/rust-lightning/blob/5718baaed947fcaa9c60d80cdf309040c0c68489/lightning/src/util/ser.rs#L72-L138>
struct BufBitcoinReader<'a, R: std::io::Read> {
    inner: &'a mut R,
    buf: [u8; 1],
    is_consumed: bool,
}

impl<'a, R: std::io::Read> BufBitcoinReader<'a, R> {
    /// Creates a [`BufBitcoinReader`] which will read from the given `inner`.
    fn new(inner: &'a mut R) -> Self {
        BufBitcoinReader {
            inner,
            buf: [0; 1],
            is_consumed: true,
        }
    }
}

impl<R: std::io::Read> bitcoin_io::Read for BufBitcoinReader<'_, R> {
    #[inline]
    fn read(&mut self, output: &mut [u8]) -> bitcoin_io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        #[allow(clippy::useless_let_if_seq)]
        let mut offset = 0;
        if !self.is_consumed {
            output[0] = self.buf[0];
            self.is_consumed = true;
            offset = 1;
        }
        Ok(self
            .inner
            .read(&mut output[offset..])
            .map(|len| len + offset)?)
    }
}

impl<R: std::io::Read> bitcoin_io::BufRead for BufBitcoinReader<'_, R> {
    #[inline]
    fn fill_buf(&mut self) -> bitcoin_io::Result<&[u8]> {
        debug_assert!(false, "rust-bitcoin doesn't actually use this");
        if self.is_consumed {
            let count = self.inner.read(&mut self.buf[..])?;
            debug_assert!(count <= 1, "read gave us a garbage length");

            // upon hitting EOF, assume the byte is already consumed
            self.is_consumed = count == 0;
        }

        if self.is_consumed {
            Ok(&[])
        } else {
            Ok(&self.buf[..])
        }
    }

    #[inline]
    fn consume(&mut self, amount: usize) {
        debug_assert!(false, "rust-bitcoin doesn't actually use this");
        if amount >= 1 {
            debug_assert_eq!(amount, 1, "Can only consume one byte");
            debug_assert!(!self.is_consumed, "Cannot consume more than had been read");
            self.is_consumed = true;
        }
    }
}

/// A writer counting number of bytes written to it
///
/// Copy&pasted from <https://github.com/SOF3/count-write> which
/// uses Apache license (and it's a trivial amount of code, repeating
/// on stack overflow).
pub struct BitoinIoWriteAdapter<W> {
    inner: W,
}

impl<W> From<W> for BitoinIoWriteAdapter<W> {
    fn from(inner: W) -> Self {
        Self { inner }
    }
}

impl<W: Write> bitcoin_io::Write for BitoinIoWriteAdapter<W> {
    fn write(&mut self, buf: &[u8]) -> bitcoin_io::Result<usize> {
        let written = self.inner.write(buf)?;
        Ok(written)
    }

    fn flush(&mut self) -> bitcoin_io::Result<()> {
        self.inner.flush().map_err(bitcoin_io::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::hashes::Hash as BitcoinHash;
    use hex::FromHex;

    use crate::ModuleDecoderRegistry;
    use crate::db::DatabaseValue;
    use crate::encoding::btc::NetworkLegacyEncodingWrapper;
    use crate::encoding::tests::{test_roundtrip, test_roundtrip_expected};
    use crate::encoding::{Decodable, Encodable};

    #[test_log::test]
    fn block_hash_roundtrip() {
        let blockhash = bitcoin::BlockHash::from_str(
            "0000000000000000000065bda8f8a88f2e1e00d9a6887a43d640e52a4c7660f2",
        )
        .unwrap();
        test_roundtrip_expected(
            &blockhash,
            &[
                242, 96, 118, 76, 42, 229, 64, 214, 67, 122, 136, 166, 217, 0, 30, 46, 143, 168,
                248, 168, 189, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        );
    }

    #[test_log::test]
    fn tx_roundtrip() {
        let transaction: Vec<u8> = FromHex::from_hex(
            "02000000000101d35b66c54cf6c09b81a8d94cd5d179719cd7595c258449452a9305ab9b12df250200000000fdffffff020cd50a0000000000160014ae5d450b71c04218e6e81c86fcc225882d7b7caae695b22100000000160014f60834ef165253c571b11ce9fa74e46692fc5ec10248304502210092062c609f4c8dc74cd7d4596ecedc1093140d90b3fd94b4bdd9ad3e102ce3bc02206bb5a6afc68d583d77d5d9bcfb6252a364d11a307f3418be1af9f47f7b1b3d780121026e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a621ef65f177ea28600000000"
        ).unwrap();
        let transaction =
            bitcoin::Transaction::from_bytes(&transaction, &ModuleDecoderRegistry::default())
                .unwrap();
        test_roundtrip_expected(
            &transaction,
            &[
                2, 0, 0, 0, 0, 1, 1, 211, 91, 102, 197, 76, 246, 192, 155, 129, 168, 217, 76, 213,
                209, 121, 113, 156, 215, 89, 92, 37, 132, 73, 69, 42, 147, 5, 171, 155, 18, 223,
                37, 2, 0, 0, 0, 0, 253, 255, 255, 255, 2, 12, 213, 10, 0, 0, 0, 0, 0, 22, 0, 20,
                174, 93, 69, 11, 113, 192, 66, 24, 230, 232, 28, 134, 252, 194, 37, 136, 45, 123,
                124, 170, 230, 149, 178, 33, 0, 0, 0, 0, 22, 0, 20, 246, 8, 52, 239, 22, 82, 83,
                197, 113, 177, 28, 233, 250, 116, 228, 102, 146, 252, 94, 193, 2, 72, 48, 69, 2,
                33, 0, 146, 6, 44, 96, 159, 76, 141, 199, 76, 215, 212, 89, 110, 206, 220, 16, 147,
                20, 13, 144, 179, 253, 148, 180, 189, 217, 173, 62, 16, 44, 227, 188, 2, 32, 107,
                181, 166, 175, 198, 141, 88, 61, 119, 213, 217, 188, 251, 98, 82, 163, 100, 209,
                26, 48, 127, 52, 24, 190, 26, 249, 244, 127, 123, 27, 61, 120, 1, 33, 2, 110, 86,
                40, 80, 110, 205, 51, 36, 46, 92, 235, 95, 218, 254, 77, 48, 102, 181, 192, 241,
                89, 179, 192, 90, 98, 30, 246, 95, 23, 126, 162, 134, 0, 0, 0, 0,
            ],
        );
    }

    #[test_log::test]
    fn txid_roundtrip() {
        let txid = bitcoin::Txid::from_str(
            "51f7ed2f23e58cc6e139e715e9ce304a1e858416edc9079dd7b74fa8d2efc09a",
        )
        .unwrap();
        test_roundtrip_expected(
            &txid,
            &[
                154, 192, 239, 210, 168, 79, 183, 215, 157, 7, 201, 237, 22, 132, 133, 30, 74, 48,
                206, 233, 21, 231, 57, 225, 198, 140, 229, 35, 47, 237, 247, 81,
            ],
        );
    }

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
            let network_legacy_encoded =
                NetworkLegacyEncodingWrapper(network).consensus_encode_to_vec();

            let network_encoded = network.consensus_encode_to_vec();

            let network_legacy_decoded = NetworkLegacyEncodingWrapper::consensus_decode_whole(
                &network_legacy_encoded,
                &ModuleDecoderRegistry::default(),
            )
            .unwrap()
            .0;

            let network_decoded = bitcoin::Network::consensus_decode_whole(
                &network_encoded,
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
            let encoding = address.consensus_encode_to_vec();
            let parsed_address = bitcoin::Address::consensus_decode_whole(
                &encoding,
                &ModuleDecoderRegistry::default(),
            )
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

    #[test_log::test]
    fn bolt11_invoice_roundtrip() {
        let invoice_str = "lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45tqcs\
			h2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5q6rmq35js88zp5dvwrv9m459tnk2zunwj5jalqtyxqulh0l\
			5gflssp5nf55ny5gcrfl30xuhzj3nphgj27rstekmr9fw3ny5989s300gyus9qyysgqcqpcrzjqw2sxwe993\
			h5pcm4dxzpvttgza8zhkqxpgffcrf5v25nwpr3cmfg7z54kuqq8rgqqqqqqqq2qqqqq9qq9qrzjqd0ylaqcl\
			j9424x9m8h2vcukcgnm6s56xfgu3j78zyqzhgs4hlpzvznlugqq9vsqqqqqqqlgqqqqqeqq9qrzjqwldmj9d\
			ha74df76zhx6l9we0vjdquygcdt3kssupehe64g6yyp5yz5rhuqqwccqqyqqqqlgqqqqjcqq9qrzjqf9e58a\
			guqr0rcun0ajlvmzq3ek63cw2w282gv3z5uupmuwvgjtq2z55qsqqg6qqqyqqqrtnqqqzq3cqygrzjqvphms\
			ywntrrhqjcraumvc4y6r8v4z5v593trte429v4hredj7ms5z52usqq9ngqqqqqqqlgqqqqqqgq9qrzjq2v0v\
			p62g49p7569ev48cmulecsxe59lvaw3wlxm7r982zxa9zzj7z5l0cqqxusqqyqqqqlgqqqqqzsqygarl9fh3\
			8s0gyuxjjgux34w75dnc6xp2l35j7es3jd4ugt3lu0xzre26yg5m7ke54n2d5sym4xcmxtl8238xxvw5h5h5\
			j5r6drg6k6zcqj0fcwg";
        let invoice = invoice_str
            .parse::<lightning_invoice::Bolt11Invoice>()
            .unwrap();
        test_roundtrip(&invoice);
    }
}
