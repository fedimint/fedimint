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
mod btc;
mod secp256k1;
mod threshold_crypto;

#[cfg(not(target_family = "wasm"))]
mod tls;

use std::any::TypeId;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{Debug, Formatter};
use std::io::{self, Error, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{cmp, mem};

use anyhow::{format_err, Context};
pub use fedimint_derive::{Decodable, Encodable};
use hex::{FromHex, ToHex};
use lightning::util::ser::{Readable, Writeable};
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
        let mut bytes = vec![];
        self.consensus_encode(&mut bytes)
            .expect("encoding to bytes can't fail for io reasons");
        // TODO: This double allocation offends real Rustaceans. We should
        // be able to go straight to String, but this use case seems under-served
        // by hex encoding crates.
        bytes.encode_hex()
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

pub use lightning::util::ser::BigSize;

impl Encodable for BigSize {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut writer = CountWrite::from(writer);
        self.write(&mut writer)?;
        Ok(usize::try_from(writer.count()).expect("can't overflow"))
    }
}

impl Decodable for BigSize {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::read(&mut SimpleBitcoinRead(r))
            .map_err(|e| DecodeError::new_custom(anyhow::anyhow!("BigSize decoding error: {e:?}")))
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

/// Specialized version of Encodable for bytes
pub fn consensus_encode_bytes<W: std::io::Write>(
    bytes: &[u8],
    writer: &mut W,
) -> Result<usize, Error> {
    let mut len = 0;
    len += (bytes.len() as u64).consensus_encode(writer)?;
    writer.write_all(bytes)?;
    len += bytes.len();
    Ok(len)
}

/// Specialized version of Encodable for static byte arrays
pub fn consensus_encode_bytes_static<const N: usize, W: std::io::Write>(
    bytes: &[u8; N],
    writer: &mut W,
) -> Result<usize, Error> {
    writer.write_all(bytes)?;
    Ok(bytes.len())
}

struct ReadBytesFromFiniteReaderOpts {
    len: usize,
    chunk_size: usize,
}

/// Read `opts.len` bytes from reader, where `opts.len` could potentially be
/// malicious.
///
/// Adapted from <https://github.com/rust-bitcoin/rust-bitcoin/blob/e2b9555070d9357fb552e56085fb6fb3f0274560/bitcoin/src/consensus/encode.rs#L659>
#[inline]
fn read_bytes_from_finite_reader<D: Read + ?Sized>(
    d: &mut D,
    mut opts: ReadBytesFromFiniteReaderOpts,
) -> Result<Vec<u8>, io::Error> {
    let mut ret = vec![];

    assert_ne!(opts.chunk_size, 0);

    while opts.len > 0 {
        let chunk_start = ret.len();
        let chunk_size = core::cmp::min(opts.len, opts.chunk_size);
        let chunk_end = chunk_start + chunk_size;
        ret.resize(chunk_end, 0u8);
        d.read_exact(&mut ret[chunk_start..chunk_end])?;
        opts.len -= chunk_size;
    }

    Ok(ret)
}

/// Specialized version of Decodable for bytes
pub fn consensus_decode_bytes<D: std::io::Read>(r: &mut D) -> Result<Vec<u8>, DecodeError> {
    consensus_decode_bytes_from_finite_reader(&mut r.take(MAX_DECODE_SIZE as u64))
}

/// Specialized version of Decodable for bytes
pub fn consensus_decode_bytes_from_finite_reader<D: std::io::Read>(
    r: &mut D,
) -> Result<Vec<u8>, DecodeError> {
    let len = u64::consensus_decode_from_finite_reader(r, &ModuleRegistry::default())?;

    let len: usize =
        usize::try_from(len).map_err(|_| DecodeError::from_str("size exceeds memory"))?;

    let opts = ReadBytesFromFiniteReaderOpts {
        len,
        chunk_size: 64 * 1024,
    };

    read_bytes_from_finite_reader(r, opts).map_err(DecodeError::from_err)
}

/// Specialized version of Decodable for fixed-size byte arrays
pub fn consensus_decode_bytes_static<const N: usize, D: std::io::Read>(
    r: &mut D,
) -> Result<[u8; N], DecodeError> {
    consensus_decode_bytes_static_from_finite_reader(&mut r.take(MAX_DECODE_SIZE as u64))
}
/// Specialized version of Decodable for fixed-size byte arrays
pub fn consensus_decode_bytes_static_from_finite_reader<const N: usize, D: std::io::Read>(
    r: &mut D,
) -> Result<[u8; N], DecodeError> {
    let mut bytes = [0u8; N];
    r.read_exact(bytes.as_mut_slice())
        .map_err(DecodeError::from_err)?;
    Ok(bytes)
}

impl_encode_decode_tuple!(T1, T2);
impl_encode_decode_tuple!(T1, T2, T3);
impl_encode_decode_tuple!(T1, T2, T3, T4);

impl<T> Encodable for &[T]
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            return consensus_encode_bytes(unsafe { mem::transmute::<&[T], &[u8]>(self) }, writer);
        }

        let mut len = 0;
        len += (self.len() as u64).consensus_encode(writer)?;

        for item in *self {
            len += item.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<T> Encodable for Vec<T>
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        (self as &[T]).consensus_encode(writer)
    }
}

impl<T> Decodable for Vec<T>
where
    T: Decodable + 'static,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            return Ok(unsafe {
                mem::transmute::<Vec<u8>, Self>(consensus_decode_bytes_from_finite_reader(d)?)
            });
        }
        let len = u64::consensus_decode_from_finite_reader(d, modules)?;

        // `collect` under the hood uses `FromIter::from_iter`, which can potentially be
        // backed by code like:
        // <https://github.com/rust-lang/rust/blob/fe03b46ee4688a99d7155b4f9dcd875b6903952d/library/alloc/src/vec/spec_from_iter_nested.rs#L31>
        // This can take `size_hint` from input iterator and pre-allocate memory
        // upfront with `Vec::with_capacity`. Because of that untrusted `len`
        // should not be used directly.
        let cap_len = cmp::min(8_000 / mem::size_of::<T>() as u64, len);

        // Up to a cap, use the (potentially specialized for better perf in stdlib)
        // `from_iter`.
        let mut v: Self = (0..cap_len)
            .map(|_| T::consensus_decode_from_finite_reader(d, modules))
            .collect::<Result<Self, DecodeError>>()?;

        // Add any excess manually avoiding any surprises.
        while (v.len() as u64) < len {
            v.push(T::consensus_decode_from_finite_reader(d, modules)?);
        }

        assert_eq!(v.len() as u64, len);

        Ok(v)
    }
}

impl<T> Encodable for VecDeque<T>
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = (self.len() as u64).consensus_encode(writer)?;
        for i in self {
            len += i.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

#[test]
fn vec_decode_sanity() {
    let buf = [
        0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // On malicious large len, return an error instead of panicking.
    assert!(Vec::<u8>::consensus_decode(&mut buf.as_slice(), &ModuleRegistry::default()).is_err());
    assert!(Vec::<u16>::consensus_decode(&mut buf.as_slice(), &ModuleRegistry::default()).is_err());
}

impl<T> Decodable for VecDeque<T>
where
    T: Decodable + 'static,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::from(Vec::<T>::consensus_decode_from_finite_reader(
            d, modules,
        )?))
    }
}

#[test]
fn vec_deque_decode_sanity() {
    let buf = [
        0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // On malicious large len, return an error instead of panicking.
    assert!(
        VecDeque::<u8>::consensus_decode(&mut buf.as_slice(), &ModuleRegistry::default()).is_err()
    );
    assert!(
        VecDeque::<u16>::consensus_decode(&mut buf.as_slice(), &ModuleRegistry::default()).is_err()
    );
}

impl<T, const SIZE: usize> Encodable for [T; SIZE]
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            return consensus_encode_bytes_static(
                unsafe { mem::transmute::<&[T; SIZE], &[u8; SIZE]>(self) },
                writer,
            );
        }

        let mut len = 0;
        for item in self {
            len += item.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

// From <https://github.com/rust-lang/rust/issues/61956>
unsafe fn horribe_array_transmute_workaround<const N: usize, A, B>(mut arr: [A; N]) -> [B; N] {
    let ptr = std::ptr::from_mut(&mut arr).cast::<[B; N]>();
    let res = unsafe { ptr.read() };
    core::mem::forget(arr);
    res
}

impl<T, const SIZE: usize> Decodable for [T; SIZE]
where
    T: Decodable + Debug + Default + Copy + 'static,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            return Ok(unsafe {
                let arr = consensus_decode_bytes_static_from_finite_reader(d)?;
                horribe_array_transmute_workaround::<SIZE, u8, T>(arr)
            });
        }
        // todo: impl without copy
        let mut data = [T::default(); SIZE];
        for item in &mut data {
            *item = T::consensus_decode_from_finite_reader(d, modules)?;
        }
        Ok(data)
    }
}

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

impl Encodable for lightning_invoice::Bolt11Invoice {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_string().consensus_encode(writer)
    }
}

impl Encodable for lightning_invoice::RoutingFees {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.base_msat.consensus_encode(writer)?;
        len += self.proportional_millionths.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for lightning_invoice::RoutingFees {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let base_msat = Decodable::consensus_decode(d, modules)?;
        let proportional_millionths = Decodable::consensus_decode(d, modules)?;
        Ok(Self {
            base_msat,
            proportional_millionths,
        })
    }
}

impl Decodable for lightning_invoice::Bolt11Invoice {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        String::consensus_decode(d, modules)?
            .parse::<Self>()
            .map_err(DecodeError::from_err)
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

impl<K, V> Encodable for BTreeMap<K, V>
where
    K: Encodable,
    V: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += (self.len() as u64).consensus_encode(writer)?;
        for (k, v) in self {
            len += k.consensus_encode(writer)?;
            len += v.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<K, V> Decodable for BTreeMap<K, V>
where
    K: Decodable + Ord,
    V: Decodable,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut res = Self::new();
        let len = u64::consensus_decode_from_finite_reader(d, modules)?;
        for _ in 0..len {
            let k = K::consensus_decode_from_finite_reader(d, modules)?;
            if res
                .last_key_value()
                .is_some_and(|(prev_key, _v)| k <= *prev_key)
            {
                return Err(DecodeError::from_str("Non-canonical encoding"));
            }
            let v = V::consensus_decode_from_finite_reader(d, modules)?;
            if res.insert(k, v).is_some() {
                return Err(DecodeError(format_err!("Duplicate key")));
            }
        }
        Ok(res)
    }
}

impl<K> Encodable for BTreeSet<K>
where
    K: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += (self.len() as u64).consensus_encode(writer)?;
        for k in self {
            len += k.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<K> Decodable for BTreeSet<K>
where
    K: Decodable + Ord,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut res = Self::new();
        let len = u64::consensus_decode_from_finite_reader(d, modules)?;
        for _ in 0..len {
            let k = K::consensus_decode_from_finite_reader(d, modules)?;
            if res.last().is_some_and(|prev_key| k <= *prev_key) {
                return Err(DecodeError::from_str("Non-canonical encoding"));
            }
            if !res.insert(k) {
                return Err(DecodeError(format_err!("Duplicate key")));
            }
        }
        Ok(res)
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

// Simple decoder implementing `bitcoin_io::Read` for `std::io::Read`.
// This is needed because `bitcoin::consensus::Decodable` requires a
// `bitcoin_io::Read`.
pub struct SimpleBitcoinRead<R: std::io::Read>(R);

impl<R: std::io::Read> bitcoin_io::Read for SimpleBitcoinRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> bitcoin_io::Result<usize> {
        self.0.read(buf).map_err(bitcoin_io::Error::from)
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
    use std::str::FromStr;

    use super::*;
    use crate::db::DatabaseValue;
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
    fn test_invoice() {
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

    #[test_log::test]
    fn test_btreemap() {
        test_roundtrip(&BTreeMap::from([
            ("a".to_string(), 1u32),
            ("b".to_string(), 2),
        ]));
    }

    #[test_log::test]
    fn test_btreeset() {
        test_roundtrip(&BTreeSet::from(["a".to_string(), "b".to_string()]));
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

    #[test]
    fn test_bitcoin_consensus_encoding() {
        // encodings should follow the bitcoin consensus encoding
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
}
