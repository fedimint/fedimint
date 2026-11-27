use std::io::{Error, Write};
use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash as BitcoinHash;
use hex::{FromHex, ToHex};
use lightning::ln::msgs;
use lightning::util::ser::{BigSize, Readable, Writeable};
use miniscript::{Descriptor, MiniscriptKey};
use serde::{Deserialize, Serialize};

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::get_network_for_address;
use crate::module::registry::ModuleDecoderRegistry;

/// Keeps a rust-bitcoin reader failure distinguishable as [`DecodeError::Io`].
fn from_bitcoin_encode_error(error: bitcoin::consensus::encode::Error) -> DecodeError {
    match error {
        bitcoin::consensus::encode::Error::Io(io) => DecodeError::Io(io.into()),
        other => DecodeError::from_err(other),
    }
}

/// Keeps a PSBT reader failure distinguishable as [`DecodeError::Io`].
fn from_psbt_error(error: bitcoin::psbt::Error) -> DecodeError {
    match error {
        bitcoin::psbt::Error::Io(io) => DecodeError::Io(io.into()),
        bitcoin::psbt::Error::ConsensusEncoding(inner) => from_bitcoin_encode_error(inner),
        other => DecodeError::from_err(other),
    }
}

fn consensus_encode_with_buffer<T: bitcoin::consensus::Encodable, W: std::io::Write>(
    value: &T,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    let mut buffered_writer = std::io::BufWriter::new(writer);
    bitcoin::consensus::Encodable::consensus_encode(value, &mut buffered_writer)?;
    buffered_writer
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?;
    Ok(())
}

macro_rules! impl_encode_decode_bridge {
    ($btc_type:ty) => {
        impl crate::encoding::Encodable for $btc_type {
            fn consensus_encode<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> Result<(), std::io::Error> {
                consensus_encode_with_buffer(self, writer)
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
                .map_err(from_bitcoin_encode_error)
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
        Self::deserialize_from_reader(&mut BufBitcoinReader::new(d)).map_err(from_psbt_error)
    }
}

impl crate::encoding::Encodable for bitcoin::Txid {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        consensus_encode_with_buffer(self, writer)
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
        .map_err(from_bitcoin_encode_error)
    }

    fn consensus_decode_hex(
        hex: &str,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = Vec::<u8>::from_hex(hex).map_err(DecodeError::from_err)?;

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
        let network = bitcoin::Network::from_magic(magic)
            .ok_or_else(|| DecodeError::custom(format!("Unknown network magic: {magic:x}")))?;
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
        .ok_or_else(|| DecodeError::from_str("Unknown network magic"))
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

        let address =
            bitcoin::Address::from_script(&script_pk, network).map_err(DecodeError::from_err)?;

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
        Self::read(&mut SimpleBitcoinRead(r)).map_err(|error| match error {
            msgs::DecodeError::ShortRead => {
                DecodeError::Io(std::io::ErrorKind::UnexpectedEof.into())
            }
            msgs::DecodeError::Io(kind) => DecodeError::Io(bitcoin_io::Error::from(kind).into()),
            other => DecodeError::custom(format!("BigSize decoding error: {other:?}")),
        })
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
        if 1 <= amount {
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
mod tests;
