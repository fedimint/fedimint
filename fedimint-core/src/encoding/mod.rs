//! Binary encoding interface suitable for
//! consensus critical encoding.
//!
//! Over time all structs that ! need to be encoded to binary will be migrated
//! to this interface.
//!
//! This code is based on corresponding `rust-bitcoin` types.
//!
//! See [`Encodable`] and [`Decodable`] for two main traits.

pub mod as_hex;
mod bls12_381;
pub mod btc;
mod collections;
mod secp256k1;
mod threshold_crypto;

#[cfg(not(target_family = "wasm"))]
mod tls;

use std::borrow::Cow;
use std::fmt::{Debug, Formatter};
use std::io::{self, Error, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
pub use fedimint_derive::{Decodable, Encodable};
use hex::{FromHex, ToHex};
use lightning::util::ser::BigSize;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::ModuleInstanceId;
use crate::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use crate::util::SafeUrl;

/// Object-safe trait for things that can encode themselves
///
/// Like `rust-bitcoin`'s `consensus_encode`, but without generics,
/// so can be used in `dyn` objects.
pub trait DynEncodable {
    fn consensus_encode_dyn(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error>;
}

impl Encodable for dyn DynEncodable {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.consensus_encode_dyn(writer)
    }
}

impl<T> DynEncodable for T
where
    T: Encodable,
{
    fn consensus_encode_dyn(
        &self,
        mut writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        <Self as Encodable>::consensus_encode(self, &mut writer)
    }
}

impl Encodable for Box<dyn DynEncodable> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        (**self).consensus_encode_dyn(writer)
    }
}

impl<T> Encodable for &T
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        (**self).consensus_encode(writer)
    }
}

/// Data which can be encoded in a consensus-consistent way
pub trait Encodable {
    /// Encode an object with a well-defined format.
    /// Returns the number of bytes written on success.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error>;

    /// [`Self::consensus_encode`] to newly allocated `Vec<u8>`
    fn consensus_encode_to_vec(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.consensus_encode(&mut bytes)
            .expect("encoding to bytes can't fail for io reasons");
        bytes
    }

    /// Encode and convert to hex string representation
    fn consensus_encode_to_hex(&self) -> String {
        // TODO: This double allocation offends real Rustaceans. We should
        // be able to go straight to String, but this use case seems under-served
        // by hex encoding crates.
        self.consensus_encode_to_vec().encode_hex()
    }

    /// Encode without storing the encoding, return the size
    fn consensus_encode_to_len(&self) -> usize {
        self.consensus_encode(&mut io::sink())
            .expect("encoding to bytes can't fail for io reasons")
    }

    /// Generate a SHA256 hash of the consensus encoding using the default hash
    /// engine for `H`.
    ///
    /// Can be used to validate all federation members agree on state without
    /// revealing the object
    fn consensus_hash<H>(&self) -> H
    where
        H: bitcoin::hashes::Hash,
        H::Engine: std::io::Write,
    {
        let mut engine = H::engine();
        self.consensus_encode(&mut engine)
            .expect("writing to HashEngine cannot fail");
        H::from_engine(engine)
    }
}

/// Maximum size, in bytes, of data we are allowed to ever decode
/// for a single value.
pub const MAX_DECODE_SIZE: usize = 16_000_000;

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable: Sized {
    /// Decode `Self` from a size-limited reader.
    ///
    /// Like `consensus_decode` but relies on the reader being limited in the
    /// amount of data it returns, e.g. by being wrapped in
    /// [`std::io::Take`].
    ///
    /// Failing to abide to this requirement might lead to memory exhaustion
    /// caused by malicious inputs.
    ///
    /// Users should default to `consensus_decode`, but when data to be decoded
    /// is already in a byte vector of a limited size, calling this function
    /// directly might be marginally faster (due to avoiding extra checks).
    ///
    /// ### Rules for trait implementations
    ///
    /// * Simple types that that have a fixed size (own and member fields),
    ///   don't have to overwrite this method, or be concern with it, should
    ///   only impl `consensus_decode`.
    /// * Types that deserialize based on decoded untrusted length should
    ///   implement `consensus_decode_from_finite_reader` only:
    ///   * Default implementation of `consensus_decode` will forward to
    ///     `consensus_decode_bytes_from_finite_reader` with the reader wrapped
    ///     by `Take`, protecting from readers that keep returning data.
    ///   * Implementation must make sure to put a cap on things like
    ///     `Vec::with_capacity` and other allocations to avoid oversized
    ///     allocations, and rely on the reader being finite and running out of
    ///     data, and collections reallocating on a legitimately oversized input
    ///     data, instead of trying to enforce arbitrary length limits.
    /// * Types that contain other types that might be require limited reader
    ///   (thus implementing `consensus_decode_from_finite_reader`), should also
    ///   implement it applying same rules, and in addition make sure to call
    ///   `consensus_decode_from_finite_reader` on all members, to avoid
    ///   creating redundant `Take` wrappers (`Take<Take<...>>`). Failure to do
    ///   so might result only in a tiny performance hit.
    #[inline]
    fn consensus_decode_from_finite_reader<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        // This method is always strictly less general than, `consensus_decode`, so it's
        // safe and make sense to default to just calling it. This way most
        // types, that don't care about protecting against resource exhaustion
        // due to malicious input, can just ignore it.
        Self::consensus_decode(r, modules)
    }

    /// Decode an object with a well-defined format.
    ///
    /// This is the method that should be implemented for a typical, fixed sized
    /// type implementing this trait. Default implementation is wrapping the
    /// reader in [`std::io::Take`] to limit the input size to
    /// [`MAX_DECODE_SIZE`], and forwards the call to
    /// [`Self::consensus_decode_from_finite_reader`], which is convenient
    /// for types that override [`Self::consensus_decode_from_finite_reader`]
    /// instead.
    #[inline]
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::consensus_decode_from_finite_reader(&mut r.take(MAX_DECODE_SIZE as u64), modules)
    }

    /// Decode an object from hex
    fn consensus_decode_hex(
        hex: &str,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::from_hex(hex)
            .map_err(anyhow::Error::from)
            .map_err(DecodeError::new_custom)?;
        let mut reader = std::io::Cursor::new(bytes);
        Decodable::consensus_decode(&mut reader, modules)
    }

    fn consensus_decode_vec(
        bytes: Vec<u8>,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut reader = std::io::Cursor::new(bytes);
        Decodable::consensus_decode(&mut reader, modules)
    }
}

impl Encodable for SafeUrl {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_string().consensus_encode(writer)
    }
}

impl Decodable for SafeUrl {
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        String::consensus_decode_from_finite_reader(d, modules)?
            .parse::<Self>()
            .map_err(DecodeError::from_err)
    }
}

#[derive(Debug, Error)]
pub struct DecodeError(pub(crate) anyhow::Error);

impl DecodeError {
    pub fn new_custom(e: anyhow::Error) -> Self {
        Self(e)
    }
}

impl From<anyhow::Error> for DecodeError {
    fn from(e: anyhow::Error) -> Self {
        Self(e)
    }
}

macro_rules! impl_encode_decode_num_as_plain {
    ($num_type:ty) => {
        impl Encodable for $num_type {
            fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
                let bytes = self.to_be_bytes();
                writer.write_all(&bytes[..])?;
                Ok(bytes.len())
            }
        }

        impl Decodable for $num_type {
            fn consensus_decode<D: std::io::Read>(
                d: &mut D,
                _modules: &ModuleDecoderRegistry,
            ) -> Result<Self, crate::encoding::DecodeError> {
                let mut bytes = [0u8; (<$num_type>::BITS / 8) as usize];
                d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
                Ok(<$num_type>::from_be_bytes(bytes))
            }
        }
    };
}

macro_rules! impl_encode_decode_num_as_bigsize {
    ($num_type:ty) => {
        impl Encodable for $num_type {
            fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
                BigSize(u64::from(*self)).consensus_encode(writer)
            }
        }

        impl Decodable for $num_type {
            fn consensus_decode<D: std::io::Read>(
                d: &mut D,
                _modules: &ModuleDecoderRegistry,
            ) -> Result<Self, crate::encoding::DecodeError> {
                let varint = BigSize::consensus_decode(d, &Default::default())
                    .context(concat!("VarInt inside ", stringify!($num_type)))?;
                <$num_type>::try_from(varint.0).map_err(crate::encoding::DecodeError::from_err)
            }
        }
    };
}

impl<T> Encodable for std::ops::RangeInclusive<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        (self.start(), self.end()).consensus_encode(writer)
    }
}

impl<T> Decodable for std::ops::RangeInclusive<T>
where
    T: Decodable,
{
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        let r = <(T, T)>::consensus_decode(d, &ModuleRegistry::default())?;
        Ok(Self::new(r.0, r.1))
    }
}

impl_encode_decode_num_as_bigsize!(u64);
impl_encode_decode_num_as_bigsize!(u32);
impl_encode_decode_num_as_bigsize!(u16);
impl_encode_decode_num_as_plain!(u8);

macro_rules! impl_encode_decode_tuple {
    ($($x:ident),*) => (
        #[allow(non_snake_case)]
        impl <$($x: Encodable),*> Encodable for ($($x),*) {
            fn consensus_encode<W: std::io::Write>(&self, s: &mut W) -> Result<usize, std::io::Error> {
                let &($(ref $x),*) = self;
                let mut len = 0;
                $(len += $x.consensus_encode(s)?;)*
                Ok(len)
            }
        }

        #[allow(non_snake_case)]
        impl<$($x: Decodable),*> Decodable for ($($x),*) {
            fn consensus_decode<D: std::io::Read>(d: &mut D, modules: &ModuleDecoderRegistry) -> Result<Self, DecodeError> {
                Ok(($({let $x = Decodable::consensus_decode(d, modules)?; $x }),*))
            }
        }
    );
}

impl_encode_decode_tuple!(T1, T2);
impl_encode_decode_tuple!(T1, T2, T3);
impl_encode_decode_tuple!(T1, T2, T3, T4);

impl<T> Encodable for Option<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        if let Some(inner) = self {
            len += 1u8.consensus_encode(writer)?;
            len += inner.consensus_encode(writer)?;
        } else {
            len += 0u8.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<T> Decodable for Option<T>
where
    T: Decodable,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let flag = u8::consensus_decode_from_finite_reader(d, modules)?;
        match flag {
            0 => Ok(None),
            1 => Ok(Some(T::consensus_decode_from_finite_reader(d, modules)?)),
            _ => Err(DecodeError::from_str(
                "Invalid flag for option enum, expected 0 or 1",
            )),
        }
    }
}

impl<T, E> Encodable for Result<T, E>
where
    T: Encodable,
    E: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;

        match self {
            Ok(value) => {
                len += 1u8.consensus_encode(writer)?;
                len += value.consensus_encode(writer)?;
            }
            Err(error) => {
                len += 0u8.consensus_encode(writer)?;
                len += error.consensus_encode(writer)?;
            }
        }

        Ok(len)
    }
}

impl<T, E> Decodable for Result<T, E>
where
    T: Decodable,
    E: Decodable,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let flag = u8::consensus_decode_from_finite_reader(d, modules)?;
        match flag {
            0 => Ok(Err(E::consensus_decode_from_finite_reader(d, modules)?)),
            1 => Ok(Ok(T::consensus_decode_from_finite_reader(d, modules)?)),
            _ => Err(DecodeError::from_str(
                "Invalid flag for option enum, expected 0 or 1",
            )),
        }
    }
}

impl<T> Encodable for Box<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.as_ref().consensus_encode(writer)
    }
}

impl<T> Decodable for Box<T>
where
    T: Decodable,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::new(T::consensus_decode_from_finite_reader(
            d, modules,
        )?))
    }
}

impl Encodable for () {
    fn consensus_encode<W: std::io::Write>(
        &self,
        _writer: &mut W,
    ) -> Result<usize, std::io::Error> {
        Ok(0)
    }
}

impl Decodable for () {
    fn consensus_decode<D: std::io::Read>(
        _d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(())
    }
}

impl Encodable for &str {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.as_bytes().consensus_encode(writer)
    }
}

impl Encodable for String {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.as_bytes().consensus_encode(writer)
    }
}

impl Decodable for String {
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::from_utf8(Decodable::consensus_decode_from_finite_reader(d, modules)?)
            .map_err(DecodeError::from_err)
    }
}

impl Encodable for SystemTime {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let duration = self.duration_since(UNIX_EPOCH).expect("valid duration");
        duration.consensus_encode_dyn(writer)
    }
}

impl Decodable for SystemTime {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let duration = Duration::consensus_decode(d, modules)?;
        Ok(UNIX_EPOCH + duration)
    }
}

impl Encodable for Duration {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut count = 0;
        count += self.as_secs().consensus_encode(writer)?;
        count += self.subsec_nanos().consensus_encode(writer)?;

        Ok(count)
    }
}

impl Decodable for Duration {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let secs = Decodable::consensus_decode(d, modules)?;
        let nsecs = Decodable::consensus_decode(d, modules)?;
        Ok(Self::new(secs, nsecs))
    }
}

impl Encodable for bool {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let bool_as_u8 = u8::from(*self);
        writer.write_all(&[bool_as_u8])?;
        Ok(1)
    }
}

impl Decodable for bool {
    fn consensus_decode<D: Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bool_as_u8 = [0u8];
        d.read_exact(&mut bool_as_u8)
            .map_err(DecodeError::from_err)?;
        match bool_as_u8[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::from_str("Out of range, expected 0 or 1")),
        }
    }
}

impl DecodeError {
    // TODO: think about better name
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &'static str) -> Self {
        #[derive(Debug)]
        struct StrError(&'static str);

        impl std::fmt::Display for StrError {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl std::error::Error for StrError {}

        Self(anyhow::Error::from(StrError(s)))
    }

    pub fn from_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self(anyhow::Error::from(e))
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl Encodable for Cow<'static, str> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.as_ref().consensus_encode(writer)
    }
}

impl Decodable for Cow<'static, str> {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Cow::Owned(String::consensus_decode(d, modules)?))
    }
}

/// A writer counting number of writes written to it
///
/// Copy&pasted from <https://github.com/SOF3/count-write> which
/// uses Apache license (and it's a trivial amount of code, repeating
/// on stack overflow).
pub struct CountWrite<W> {
    inner: W,
    count: u64,
}

impl<W> CountWrite<W> {
    /// Returns the number of bytes successfully written so far
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Extracts the inner writer, discarding this wrapper
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W> From<W> for CountWrite<W> {
    fn from(inner: W) -> Self {
        Self { inner, count: 0 }
    }
}

impl<W: Write> bitcoin_io::Write for CountWrite<W> {
    fn write(&mut self, buf: &[u8]) -> bitcoin_io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.count += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> bitcoin_io::Result<()> {
        self.inner.flush().map_err(bitcoin_io::Error::from)
    }
}

/// A type that decodes `module_instance_id`-prefixed `T`s even
/// when corresponding `Decoder` is not available.
///
/// All dyn-module types are encoded as:
///
/// ```norust
/// module_instance_id | len_u64 | data
/// ```
///
/// So clients that don't have a corresponding module, can read
/// the `len_u64` and skip the amount of data specified in it.
///
/// This type makes it more convenient. It's possible to attempt
/// to retry decoding after more modules become available by using
/// [`DynRawFallback::redecode_raw`].
///
/// Notably this struct does not ignore any errors. It only skips
/// decoding when the module decoder is not available.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum DynRawFallback<T> {
    Raw {
        module_instance_id: ModuleInstanceId,
        #[serde(with = "::fedimint_core::encoding::as_hex")]
        raw: Vec<u8>,
    },
    Decoded(T),
}

impl<T> DynRawFallback<T>
where
    T: Decodable + 'static,
{
    /// Get the decoded `T` or `None` if not decoded yet
    pub fn decoded(self) -> Option<T> {
        match self {
            Self::Raw { .. } => None,
            Self::Decoded(v) => Some(v),
        }
    }

    /// Convert into the decoded `T` and panic if not decoded yet
    pub fn expect_decoded(self) -> T {
        match self {
            Self::Raw { .. } => {
                panic!("Expected decoded value. Possibly `redecode_raw` call is missing.")
            }
            Self::Decoded(v) => v,
        }
    }

    /// Get the decoded `T` and panic if not decoded yet
    pub fn expect_decoded_ref(&self) -> &T {
        match self {
            Self::Raw { .. } => {
                panic!("Expected decoded value. Possibly `redecode_raw` call is missing.")
            }
            Self::Decoded(v) => v,
        }
    }

    /// Attempt to re-decode raw values with new set of of `modules`
    ///
    /// In certain contexts it might be necessary to try again with
    /// a new set of modules.
    pub fn redecode_raw(
        self,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        Ok(match self {
            Self::Raw {
                module_instance_id,
                raw,
            } => match decoders.get(module_instance_id) {
                Some(decoder) => Self::Decoded(decoder.decode_complete(
                    &mut &raw[..],
                    raw.len() as u64,
                    module_instance_id,
                    decoders,
                )?),
                None => Self::Raw {
                    module_instance_id,
                    raw,
                },
            },
            Self::Decoded(v) => Self::Decoded(v),
        })
    }
}

impl<T> From<T> for DynRawFallback<T> {
    fn from(value: T) -> Self {
        Self::Decoded(value)
    }
}

impl<T> Decodable for DynRawFallback<T>
where
    T: Decodable + 'static,
{
    fn consensus_decode_from_finite_reader<R: std::io::Read>(
        reader: &mut R,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        let module_instance_id =
            fedimint_core::core::ModuleInstanceId::consensus_decode_from_finite_reader(
                reader, decoders,
            )?;
        Ok(match decoders.get(module_instance_id) {
            Some(decoder) => {
                let total_len_u64 = u64::consensus_decode_from_finite_reader(reader, decoders)?;
                Self::Decoded(decoder.decode_complete(
                    reader,
                    total_len_u64,
                    module_instance_id,
                    decoders,
                )?)
            }
            None => {
                // since the decoder is not available, just read the raw data
                Self::Raw {
                    module_instance_id,
                    raw: Vec::consensus_decode_from_finite_reader(reader, decoders)?,
                }
            }
        })
    }
}

impl<T> Encodable for DynRawFallback<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        match self {
            Self::Raw {
                module_instance_id,
                raw,
            } => {
                let mut written = module_instance_id.consensus_encode(writer)?;
                written += raw.consensus_encode(writer)?;
                Ok(written)
            }
            Self::Decoded(v) => v.consensus_encode(writer),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::io::Cursor;

    use super::*;
    use crate::encoding::{Decodable, Encodable};

    pub(crate) fn test_roundtrip<T>(value: &T)
    where
        T: Encodable + Decodable + Eq + Debug,
    {
        let mut bytes = Vec::new();
        let len = value.consensus_encode(&mut bytes).unwrap();
        assert_eq!(len, bytes.len());

        let mut cursor = Cursor::new(bytes);
        let decoded = T::consensus_decode(&mut cursor, &ModuleDecoderRegistry::default()).unwrap();
        assert_eq!(value, &decoded);
        assert_eq!(cursor.position(), len as u64);
    }

    pub(crate) fn test_roundtrip_expected<T>(value: &T, expected: &[u8])
    where
        T: Encodable + Decodable + Eq + Debug,
    {
        let mut bytes = Vec::new();
        let len = value.consensus_encode(&mut bytes).unwrap();
        assert_eq!(len, bytes.len());
        assert_eq!(&expected, &bytes);

        let mut cursor = Cursor::new(bytes);
        let decoded = T::consensus_decode(&mut cursor, &ModuleDecoderRegistry::default()).unwrap();
        assert_eq!(value, &decoded);
        assert_eq!(cursor.position(), len as u64);
    }

    #[derive(Debug, Eq, PartialEq, Encodable, Decodable)]
    enum NoDefaultEnum {
        Foo,
        Bar(u32, String),
        Baz { baz: u8 },
    }

    #[derive(Debug, Eq, PartialEq, Encodable, Decodable)]
    enum DefaultEnum {
        Foo,
        Bar(u32, String),
        #[encodable_default]
        Default {
            variant: u64,
            bytes: Vec<u8>,
        },
    }

    #[test_log::test]
    fn test_derive_enum_no_default_roundtrip_success() {
        let enums = [
            NoDefaultEnum::Foo,
            NoDefaultEnum::Bar(
                42,
                "The answer to life, the universe, and everything".to_string(),
            ),
            NoDefaultEnum::Baz { baz: 0 },
        ];

        for e in enums {
            test_roundtrip(&e);
        }
    }

    #[test_log::test]
    fn test_derive_enum_no_default_decode_fail() {
        let unknown_variant = DefaultEnum::Default {
            variant: 42,
            bytes: vec![0, 1, 2, 3],
        };
        let mut unknown_variant_encoding = vec![];
        unknown_variant
            .consensus_encode(&mut unknown_variant_encoding)
            .unwrap();

        let mut cursor = Cursor::new(&unknown_variant_encoding);
        let decode_res = NoDefaultEnum::consensus_decode(&mut cursor, &ModuleRegistry::default());

        match decode_res {
            Ok(_) => panic!("Should return error"),
            Err(e) => assert!(e.to_string().contains("Invalid enum variant")),
        }
    }

    #[test_log::test]
    fn test_derive_enum_default_decode_success() {
        let unknown_variant = NoDefaultEnum::Baz { baz: 123 };
        let mut unknown_variant_encoding = vec![];
        unknown_variant
            .consensus_encode(&mut unknown_variant_encoding)
            .unwrap();

        let mut cursor = Cursor::new(&unknown_variant_encoding);
        let decode_res = DefaultEnum::consensus_decode(&mut cursor, &ModuleRegistry::default());

        assert_eq!(
            decode_res.unwrap(),
            DefaultEnum::Default {
                variant: 2,
                bytes: vec![123],
            }
        );
    }

    #[test_log::test]
    fn test_derive_struct() {
        #[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
        struct TestStruct {
            vec: Vec<u8>,
            num: u32,
        }

        let reference = TestStruct {
            vec: vec![1, 2, 3],
            num: 42,
        };
        let bytes = [3, 1, 2, 3, 42];

        test_roundtrip_expected(&reference, &bytes);
    }

    #[test_log::test]
    fn test_derive_tuple_struct() {
        #[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
        struct TestStruct(Vec<u8>, u32);

        let reference = TestStruct(vec![1, 2, 3], 42);
        let bytes = [3, 1, 2, 3, 42];

        test_roundtrip_expected(&reference, &bytes);
    }

    #[test_log::test]
    fn test_derive_enum() {
        #[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
        enum TestEnum {
            Foo(Option<u64>),
            Bar { bazz: Vec<u8> },
        }

        let test_cases = [
            (TestEnum::Foo(Some(42)), vec![0, 2, 1, 42]),
            (TestEnum::Foo(None), vec![0, 1, 0]),
            (
                TestEnum::Bar {
                    bazz: vec![1, 2, 3],
                },
                vec![1, 4, 3, 1, 2, 3],
            ),
        ];

        for (reference, bytes) in test_cases {
            test_roundtrip_expected(&reference, &bytes);
        }
    }

    #[test_log::test]
    fn test_systemtime() {
        test_roundtrip(&fedimint_core::time::now());
    }

    #[test]
    fn test_derive_empty_enum_decode() {
        #[derive(Debug, Encodable, Decodable)]
        enum NotConstructable {}

        let vec = vec![42u8];
        let mut cursor = Cursor::new(vec);

        assert!(
            NotConstructable::consensus_decode(&mut cursor, &ModuleDecoderRegistry::default())
                .is_err()
        );
    }

    #[test]
    fn test_custom_index_enum() {
        #[derive(Debug, PartialEq, Eq, Encodable, Decodable)]
        enum Old {
            Foo,
            Bar,
            Baz,
        }

        #[derive(Debug, PartialEq, Eq, Encodable, Decodable)]
        enum New {
            #[encodable(index = 0)]
            Foo,
            #[encodable(index = 2)]
            Baz,
            #[encodable_default]
            Default { variant: u64, bytes: Vec<u8> },
        }

        let test_vector = vec![
            (Old::Foo, New::Foo),
            (
                Old::Bar,
                New::Default {
                    variant: 1,
                    bytes: vec![],
                },
            ),
            (Old::Baz, New::Baz),
        ];

        for (old, new) in test_vector {
            let old_bytes = old.consensus_encode_to_vec();
            let decoded_new = New::consensus_decode_vec(old_bytes, &ModuleRegistry::default())
                .expect("Decoding failed");
            assert_eq!(decoded_new, new);
        }
    }

    fn encode_value<T: Encodable>(value: &T) -> Vec<u8> {
        let mut writer = Vec::new();
        value.consensus_encode(&mut writer).unwrap();
        writer
    }

    fn decode_value<T: Decodable>(bytes: &Vec<u8>) -> T {
        T::consensus_decode(&mut Cursor::new(bytes), &ModuleDecoderRegistry::default()).unwrap()
    }

    fn keeps_ordering_after_serialization<T: Ord + Encodable + Decodable + Debug>(mut vec: Vec<T>) {
        vec.sort();
        let mut encoded = vec.iter().map(encode_value).collect::<Vec<_>>();
        encoded.sort();
        let decoded = encoded.iter().map(decode_value).collect::<Vec<_>>();
        for (i, (a, b)) in vec.iter().zip(decoded.iter()).enumerate() {
            assert_eq!(a, b, "difference at index {i}");
        }
    }

    #[test]
    fn test_lexicographical_sorting() {
        #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Encodable, Decodable)]
        struct TestAmount(u64);

        #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Encodable, Decodable)]
        struct TestComplexAmount(u16, u32, u64);

        #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Encodable, Decodable)]
        struct Text(String);

        let amounts = (0..20000).map(TestAmount).collect::<Vec<_>>();
        keeps_ordering_after_serialization(amounts);

        let complex_amounts = (10..20000)
            .flat_map(|i| {
                (i - 1..=i + 1).flat_map(move |j| {
                    (i - 1..=i + 1).map(move |k| TestComplexAmount(i as u16, j as u32, k as u64))
                })
            })
            .collect::<Vec<_>>();
        keeps_ordering_after_serialization(complex_amounts);

        let texts = (' '..'~')
            .flat_map(|i| {
                (' '..'~')
                    .map(|j| Text(format!("{i}{j}")))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        keeps_ordering_after_serialization(texts);

        // bitcoin structures are not lexicographically sortable so we cannot
        // test them here. in future we may crate a wrapper type that is
        // lexicographically sortable to use when needed
    }
}
