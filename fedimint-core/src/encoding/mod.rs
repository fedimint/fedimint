//! Binary encoding interface suitable for
//! consensus critical encoding.
//!
//! Over time all structs that ! need to be encoded to binary will be migrated
//! to this interface.
//!
//! This code is based on corresponding `rust-bitcoin` types.
//!
//! See [`Encodable`] and [`Decodable`] for two main traits.

pub mod as_base64;
pub mod as_hex;
mod bls12_381;
pub mod btc;
mod collections;
mod iroh;
mod secp256k1;
mod threshold_crypto;

use std::borrow::Cow;
use std::cmp;
use std::fmt::{Debug, Display};
use std::io::{self, Error, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::hashes::sha256;
pub use fedimint_derive::{Decodable, Encodable};
use hex::{FromHex, ToHex};
use lightning::util::ser::BigSize;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::ModuleInstanceId;
use crate::module::registry::ModuleDecoderRegistry;
use crate::util::SafeUrl;

/// A writer counting number of bytes written to it
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
}

impl<W> From<W> for CountWrite<W> {
    fn from(inner: W) -> Self {
        Self { inner, count: 0 }
    }
}

impl<W: Write> io::Write for CountWrite<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.count += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Object-safe trait for things that can encode themselves
///
/// Like `rust-bitcoin`'s `consensus_encode`, but without generics,
/// so can be used in `dyn` objects.
pub trait DynEncodable {
    fn consensus_encode_dyn(&self, writer: &mut dyn std::io::Write) -> Result<(), std::io::Error>;
}

impl Encodable for dyn DynEncodable {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
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
    ) -> Result<(), std::io::Error> {
        <Self as Encodable>::consensus_encode(self, &mut writer)
    }
}

impl Encodable for Box<dyn DynEncodable> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        (**self).consensus_encode_dyn(writer)
    }
}

impl<T> Encodable for &T
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        (**self).consensus_encode(writer)
    }
}

/// Data which can be encoded in a consensus-consistent way
pub trait Encodable {
    /// Encode an object with a well-defined format.
    /// Returns the number of bytes written on success.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error>;

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
    fn consensus_encode_to_len(&self) -> u64 {
        let mut writer = CountWrite::from(io::sink());
        self.consensus_encode(&mut writer)
            .expect("encoding to bytes can't fail for io reasons");

        writer.count()
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

    /// [`Self::consensus_hash`] for [`bitcoin::hashes::sha256::Hash`]
    fn consensus_hash_sha256(&self) -> sha256::Hash {
        self.consensus_hash()
    }
}

/// Maximum size, in bytes, of data we are allowed to ever decode
/// for a single value.
pub const MAX_DECODE_SIZE: usize = 16_000_000;

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable: Sized {
    /// Decode `Self` from a size-limited reader.
    ///
    /// Like `consensus_decode_partial` but relies on the reader being limited
    /// in the amount of data it returns, e.g. by being wrapped in
    /// [`std::io::Take`].
    ///
    /// Failing to abide to this requirement might lead to memory exhaustion
    /// caused by malicious inputs.
    ///
    /// Users should default to `consensus_decode_partial`, but when data to be
    /// decoded is already in a byte vector of a limited size, calling this
    /// function directly might be marginally faster (due to avoiding extra
    /// checks).
    ///
    /// ### Rules for trait implementations
    ///
    /// * Simple types that that have a fixed size (own and member fields),
    ///   don't have to overwrite this method, or be concern with it, should
    ///   only impl `consensus_decode_partial`.
    /// * Types that deserialize based on decoded untrusted length should
    ///   implement `consensus_decode_partial_from_finite_reader` only:
    ///   * Default implementation of `consensus_decode_partial` will forward to
    ///     `consensus_decode_partial_from_finite_reader` with the reader
    ///     wrapped by `Take`, protecting from readers that keep returning data.
    ///   * Implementation must make sure to put a cap on things like
    ///     `Vec::with_capacity` and other allocations to avoid oversized
    ///     allocations, and rely on the reader being finite and running out of
    ///     data, and collections reallocating on a legitimately oversized input
    ///     data, instead of trying to enforce arbitrary length limits.
    /// * Types that contain other types that might be require limited reader
    ///   (thus implementing `consensus_decode_partial_from_finite_reader`),
    ///   should also implement it applying same rules, and in addition make
    ///   sure to call `consensus_decode_partial_from_finite_reader` on all
    ///   members, to avoid creating redundant `Take` wrappers
    ///   (`Take<Take<...>>`). Failure to do so might result only in a tiny
    ///   performance hit.
    #[inline]
    fn consensus_decode_partial_from_finite_reader<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        // This method is always strictly less general than, `consensus_decode_partial`,
        // so it's safe and make sense to default to just calling it. This way
        // most types, that don't care about protecting against resource
        // exhaustion due to malicious input, can just ignore it.
        Self::consensus_decode_partial(r, modules)
    }

    #[inline]
    fn consensus_decode_whole(
        slice: &[u8],
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let total_len = slice.len() as u64;

        let r = &mut &slice[..];
        let mut r = Read::take(r, total_len);

        // This method is always strictly less general than, `consensus_decode_partial`,
        // so it's safe and make sense to default to just calling it. This way
        // most types, that don't care about protecting against resource
        // exhaustion due to malicious input, can just ignore it.
        let res = Self::consensus_decode_partial_from_finite_reader(&mut r, modules)?;
        let left = r.limit();

        if left != 0 {
            return Err(fedimint_core::encoding::DecodeError::custom(format!(
                "Type did not consume all bytes during decoding; expected={total_len}; \
                 left={left}; type={}",
                std::any::type_name::<Self>(),
            )));
        }
        Ok(res)
    }
    /// Decode an object with a well-defined format.
    ///
    /// This is the method that should be implemented for a typical, fixed sized
    /// type implementing this trait. Default implementation is wrapping the
    /// reader in [`std::io::Take`] to limit the input size to
    /// [`MAX_DECODE_SIZE`], and forwards the call to
    /// [`Self::consensus_decode_partial_from_finite_reader`], which is
    /// convenient for types that override
    /// [`Self::consensus_decode_partial_from_finite_reader`] instead.
    #[inline]
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::consensus_decode_partial_from_finite_reader(
            &mut r.take(MAX_DECODE_SIZE as u64),
            modules,
        )
    }

    /// Decode an object from hex
    fn consensus_decode_hex(
        hex: &str,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::from_hex(hex).map_err(DecodeError::from_err)?;
        Decodable::consensus_decode_whole(&bytes, modules)
    }
}

/// Encodes a timestamp as the legacy `(seconds, nanoseconds)` `SystemTime`
/// representation.
///
/// Existing encoded types use this only to preserve their stored
/// representation. It panics when `time` precedes the Unix epoch.
pub fn encode_legacy_system_time<W: std::io::Write>(
    time: &SystemTime,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .expect("timestamps before the Unix epoch are unsupported");
    duration.consensus_encode_dyn(writer)
}

/// Decodes a timestamp from the legacy `(seconds, nanoseconds)` representation.
///
/// Existing encoded types use this only to preserve their stored
/// representation.
pub fn decode_legacy_system_time_from_finite_reader<D: std::io::Read>(
    decoder: &mut D,
    modules: &ModuleDecoderRegistry,
) -> Result<SystemTime, DecodeError> {
    let duration = Duration::consensus_decode_partial_from_finite_reader(decoder, modules)?;
    // `UNIX_EPOCH + duration` panics ("overflow when adding duration to instant")
    // instead of erroring when `duration` is past what `SystemTime` can hold. A
    // decoder must not abort the process on arbitrary bytes, so use the checked
    // form. Anything that round-trips today still round-trips.
    UNIX_EPOCH
        .checked_add(duration)
        .ok_or_else(|| DecodeError::from_str("SystemTime overflow: duration too large"))
}

/// Encodes an optional timestamp in the legacy `SystemTime` representation.
///
/// Existing encoded types use this only to preserve their stored
/// representation.
pub fn encode_legacy_option_system_time<W: std::io::Write>(
    time: &Option<SystemTime>,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    match time {
        Some(time) => {
            1u8.consensus_encode(writer)?;
            encode_legacy_system_time(time, writer)
        }
        None => 0u8.consensus_encode(writer),
    }
}

/// Decodes an optional timestamp in the legacy `SystemTime` representation.
///
/// Existing encoded types use this only to preserve their stored
/// representation.
pub fn decode_legacy_option_system_time_from_finite_reader<D: std::io::Read>(
    decoder: &mut D,
    modules: &ModuleDecoderRegistry,
) -> Result<Option<SystemTime>, DecodeError> {
    match u8::consensus_decode_partial_from_finite_reader(decoder, modules)? {
        0 => Ok(None),
        1 => Ok(Some(decode_legacy_system_time_from_finite_reader(
            decoder, modules,
        )?)),
        _ => Err(DecodeError::from_str(
            "Invalid flag for option enum, expected 0 or 1",
        )),
    }
}

/// Decodes a field from a finite reader and annotates errors with its schema
/// context.
pub fn decode_field_from_finite_reader<T: Decodable, D: std::io::Read>(
    decoder: &mut D,
    modules: &ModuleDecoderRegistry,
    context: &'static str,
) -> Result<T, DecodeError> {
    with_decoding_context(
        T::consensus_decode_partial_from_finite_reader(decoder, modules),
        context,
    )
}

/// Adds schema context to an error returned while decoding a field.
pub fn with_decoding_context<T>(
    result: Result<T, DecodeError>,
    context: &'static str,
) -> Result<T, DecodeError> {
    result.context(context)
}

/// Failure to consensus-decode a value.
///
/// `Display` prints only the outermost layer: the context of the decoding step
/// that failed, or the leaf cause when there is no context. The full chain is
/// reachable through [`std::error::Error::source`] and printed flat by
/// [`FmtCompact::fmt_compact`](crate::util::FmtCompact).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The reader failed or ran out of input.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The input names an enum variant the type does not have.
    #[error("Invalid enum variant {variant} while decoding {type_name}")]
    InvalidVariant {
        /// The variant index found in the input.
        variant: u64,
        /// The name of the type being decoded.
        type_name: &'static str,
    },
    /// A decoding step failed; `context` names the step and `source` says why.
    #[error("{context}")]
    Context {
        /// The decoding step that failed.
        context: String,
        /// Why it failed.
        #[source]
        source: Box<Self>,
    },
    /// The input decoded but is not a valid value of the type; the source
    /// says why.
    #[error(transparent)]
    Invalid(Box<dyn std::error::Error + Send + Sync>),
    /// The input is malformed in a way only a message describes.
    #[error("{message}")]
    Custom {
        /// What is wrong with the input.
        message: String,
    },
}

impl DecodeError {
    /// A decode failure described by a message.
    pub fn custom(message: impl Into<String>) -> Self {
        Self::Custom {
            message: message.into(),
        }
    }

    /// A decode failure described by a static message.
    // TODO: think about better name
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &'static str) -> Self {
        Self::custom(s)
    }

    /// A decode failure caused by a typed error, shown as that error.
    pub fn from_err<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Invalid(Box::new(e))
    }

    /// Wraps this error in the context of the decoding step that failed.
    pub fn context(self, context: impl Display) -> Self {
        Self::Context {
            context: context.to_string(),
            source: Box::new(self),
        }
    }
}

/// Adds the context of a decoding step to a failed result.
///
/// Implemented for every `Result` whose error converts into [`DecodeError`],
/// so it applies to results of `Decodable` calls and to `std::io::Result`.
/// Its method names match `anyhow::Context`'s; where both traits are in scope,
/// call it as `DecodeContext::context(result, ..)` to avoid the clash.
pub trait DecodeContext<T> {
    /// Wraps the error in `context`.
    fn context<C>(self, context: C) -> Result<T, DecodeError>
    where
        C: Display;

    /// Wraps the error in the context produced by `context`, which only runs
    /// on failure.
    fn with_context<C, F>(self, context: F) -> Result<T, DecodeError>
    where
        C: Display,
        F: FnOnce() -> C;
}

impl<T, E> DecodeContext<T> for Result<T, E>
where
    E: Into<DecodeError>,
{
    fn context<C>(self, context: C) -> Result<T, DecodeError>
    where
        C: Display,
    {
        self.map_err(|error| error.into().context(context))
    }

    fn with_context<C, F>(self, context: F) -> Result<T, DecodeError>
    where
        C: Display,
        F: FnOnce() -> C,
    {
        self.map_err(|error| error.into().context(context()))
    }
}

impl Encodable for SafeUrl {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.to_string().consensus_encode(writer)
    }
}

impl Decodable for SafeUrl {
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        String::consensus_decode_partial_from_finite_reader(d, modules)?
            .parse::<Self>()
            .map_err(DecodeError::from_err)
    }
}

macro_rules! impl_encode_decode_num_as_plain {
    ($num_type:ty) => {
        impl Encodable for $num_type {
            fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
                let bytes = self.to_be_bytes();
                writer.write_all(&bytes[..])?;
                Ok(())
            }
        }

        impl Decodable for $num_type {
            fn consensus_decode_partial<D: std::io::Read>(
                d: &mut D,
                _modules: &ModuleDecoderRegistry,
            ) -> Result<Self, crate::encoding::DecodeError> {
                let mut bytes = [0u8; (<$num_type>::BITS / 8) as usize];
                d.read_exact(&mut bytes)?;
                Ok(<$num_type>::from_be_bytes(bytes))
            }
        }
    };
}

macro_rules! impl_encode_decode_num_as_bigsize {
    ($num_type:ty) => {
        impl Encodable for $num_type {
            fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
                BigSize(u64::from(*self)).consensus_encode(writer)
            }
        }

        impl Decodable for $num_type {
            fn consensus_decode_partial<D: std::io::Read>(
                d: &mut D,
                _modules: &ModuleDecoderRegistry,
            ) -> Result<Self, crate::encoding::DecodeError> {
                let varint = BigSize::consensus_decode_partial(d, &Default::default())?;
                <$num_type>::try_from(varint.0).map_err(crate::encoding::DecodeError::from_err)
            }
        }
    };
}

impl_encode_decode_num_as_bigsize!(u64);
impl_encode_decode_num_as_bigsize!(u32);
impl_encode_decode_num_as_bigsize!(u16);
impl_encode_decode_num_as_plain!(u8);

macro_rules! impl_encode_decode_tuple {
    ($($x:ident),*) => (
        #[allow(non_snake_case)]
        impl <$($x: Encodable),*> Encodable for ($($x),*) {
            fn consensus_encode<W: std::io::Write>(&self, s: &mut W) -> Result<(), std::io::Error> {
                let &($(ref $x),*) = self;
                $($x.consensus_encode(s)?;)*
                Ok(())
            }
        }

        #[allow(non_snake_case)]
        impl<$($x: Decodable),*> Decodable for ($($x),*) {
            fn consensus_decode_partial<D: std::io::Read>(d: &mut D, modules: &ModuleDecoderRegistry) -> Result<Self, DecodeError> {
                Ok(($({let $x = Decodable::consensus_decode_partial(d, modules)?; $x }),*))
            }
        }
    );
}

impl_encode_decode_tuple!(T1, T2);
impl_encode_decode_tuple!(T1, T2, T3);
impl_encode_decode_tuple!(T1, T2, T3, T4);
impl_encode_decode_tuple!(T1, T2, T3, T4, T5);
impl_encode_decode_tuple!(T1, T2, T3, T4, T5, T6);

impl<T> Encodable for Option<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        if let Some(inner) = self {
            1u8.consensus_encode(writer)?;
            inner.consensus_encode(writer)?;
        } else {
            0u8.consensus_encode(writer)?;
        }
        Ok(())
    }
}

impl<T> Decodable for Option<T>
where
    T: Decodable,
{
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let flag = u8::consensus_decode_partial_from_finite_reader(d, modules)?;
        match flag {
            0 => Ok(None),
            1 => Ok(Some(T::consensus_decode_partial_from_finite_reader(
                d, modules,
            )?)),
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
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        match self {
            Ok(value) => {
                1u8.consensus_encode(writer)?;
                value.consensus_encode(writer)?;
            }
            Err(error) => {
                0u8.consensus_encode(writer)?;
                error.consensus_encode(writer)?;
            }
        }

        Ok(())
    }
}

impl<T, E> Decodable for Result<T, E>
where
    T: Decodable,
    E: Decodable,
{
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let flag = u8::consensus_decode_partial_from_finite_reader(d, modules)?;
        match flag {
            0 => Ok(Err(E::consensus_decode_partial_from_finite_reader(
                d, modules,
            )?)),
            1 => Ok(Ok(T::consensus_decode_partial_from_finite_reader(
                d, modules,
            )?)),
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
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.as_ref().consensus_encode(writer)
    }
}

impl<T> Decodable for Box<T>
where
    T: Decodable,
{
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::new(T::consensus_decode_partial_from_finite_reader(
            d, modules,
        )?))
    }
}

impl Encodable for () {
    fn consensus_encode<W: std::io::Write>(&self, _writer: &mut W) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl Decodable for () {
    fn consensus_decode_partial<D: std::io::Read>(
        _d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(())
    }
}

impl Encodable for &str {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.as_bytes().consensus_encode(writer)
    }
}

impl Encodable for String {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.as_bytes().consensus_encode(writer)
    }
}

impl Decodable for String {
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::from_utf8(Decodable::consensus_decode_partial_from_finite_reader(
            d, modules,
        )?)
        .map_err(DecodeError::from_err)
    }
}

impl Encodable for Duration {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.as_secs().consensus_encode(writer)?;
        self.subsec_nanos().consensus_encode(writer)?;

        Ok(())
    }
}

impl Decodable for Duration {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let secs = Decodable::consensus_decode_partial(d, modules)?;
        let nsecs = Decodable::consensus_decode_partial(d, modules)?;
        // The encoder writes `subsec_nanos()`, which is always below one billion,
        // so a larger `nsecs` is never something we wrote. Accepting it makes the
        // encoding non-canonical and lets `Duration::new` panic when the carried
        // second overflows `secs`.
        if 1_000_000_000 <= nsecs {
            return Err(DecodeError::from_str("Duration nanoseconds out of range"));
        }
        Ok(Self::new(secs, nsecs))
    }
}

impl Encodable for bool {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        let bool_as_u8 = u8::from(*self);
        writer.write_all(&[bool_as_u8])?;
        Ok(())
    }
}

impl Decodable for bool {
    fn consensus_decode_partial<D: Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bool_as_u8 = [0u8];
        d.read_exact(&mut bool_as_u8)?;
        match bool_as_u8[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::from_str("Out of range, expected 0 or 1")),
        }
    }
}

impl Encodable for Cow<'static, str> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.as_ref().consensus_encode(writer)
    }
}

impl Decodable for Cow<'static, str> {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Cow::Owned(String::consensus_decode_partial(d, modules)?))
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DynRawFallback<T> {
    Raw {
        module_instance_id: ModuleInstanceId,
        #[serde(with = "::fedimint_core::encoding::as_hex")]
        raw: Vec<u8>,
    },
    Decoded(T),
}

impl<T> cmp::PartialEq for DynRawFallback<T>
where
    T: cmp::PartialEq + Encodable,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Raw {
                    module_instance_id: mid_self,
                    raw: raw_self,
                },
                Self::Raw {
                    module_instance_id: mid_other,
                    raw: raw_other,
                },
            ) => mid_self.eq(mid_other) && raw_self.eq(raw_other),
            (r @ Self::Raw { .. }, d @ Self::Decoded(_))
            | (d @ Self::Decoded(_), r @ Self::Raw { .. }) => {
                r.consensus_encode_to_vec() == d.consensus_encode_to_vec()
            }
            (Self::Decoded(s), Self::Decoded(o)) => s == o,
        }
    }
}

impl<T> cmp::Eq for DynRawFallback<T> where T: cmp::Eq + Encodable {}

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
    fn consensus_decode_partial_from_finite_reader<R: std::io::Read>(
        reader: &mut R,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        let module_instance_id =
            fedimint_core::core::ModuleInstanceId::consensus_decode_partial_from_finite_reader(
                reader, decoders,
            )?;
        Ok(match decoders.get(module_instance_id) {
            Some(decoder) => {
                let total_len_u64 =
                    u64::consensus_decode_partial_from_finite_reader(reader, decoders)?;
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
                    raw: Vec::consensus_decode_partial_from_finite_reader(reader, decoders)?,
                }
            }
        })
    }
}

impl<T> Encodable for DynRawFallback<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        match self {
            Self::Raw {
                module_instance_id,
                raw,
            } => {
                module_instance_id.consensus_encode(writer)?;
                raw.consensus_encode(writer)?;
                Ok(())
            }
            Self::Decoded(v) => v.consensus_encode(writer),
        }
    }
}

#[cfg(test)]
mod tests;
