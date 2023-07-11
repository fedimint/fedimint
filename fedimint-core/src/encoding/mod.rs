//! This module defines a binary encoding interface which is more suitable for
//! consensus critical encoding than e.g. `bincode`. Over time all structs that
//! need to be encoded to binary will be migrated to this interface.

mod btc;
mod secp256k1;
mod tbs;

#[cfg(not(target_family = "wasm"))]
mod tls;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};
use std::io::{self, Error, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{cmp, mem};

use anyhow::format_err;
use bitcoin_hashes::hex::{FromHex, ToHex};
pub use fedimint_derive::{Decodable, Encodable, UnzipConsensus};
use lightning::util::ser::{Readable, Writeable};
use thiserror::Error;
use url::Url;

use crate::module::registry::ModuleDecoderRegistry;

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

/// Data which can be encoded in a consensus-consistent way
pub trait Encodable {
    /// Encode an object with a well-defined format.
    /// Returns the number of bytes written on success.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error>;

    /// [`Self::consensus_encode`] to newly allocated `Vec<u8>`
    fn consensus_encode_to_vec(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut bytes = vec![];
        self.consensus_encode(&mut bytes)?;
        Ok(bytes)
    }

    fn consensus_encode_to_hex(&self) -> Result<String, std::io::Error> {
        let mut bytes = vec![];
        self.consensus_encode(&mut bytes)?;
        Ok(bytes.to_hex())
    }

    /// Generate a SHA256 hash of the consensus encoding using the default hash
    /// engine for `H`.
    ///
    /// Can be used to validate all federation members agree on state without
    /// revealing the object
    fn consensus_hash<H>(&self) -> H
    where
        H: bitcoin_hashes::Hash,
        H::Engine: std::io::Write,
    {
        let mut engine = H::engine();
        self.consensus_encode(&mut engine)
            .expect("writing to HashEngine cannot fail");
        H::from_engine(engine)
    }
}

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError>;

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
}

impl Encodable for Url {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_string().consensus_encode(writer)
    }
}

impl Decodable for Url {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        String::consensus_decode(d, modules)?
            .parse::<Url>()
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
        BigSize::read(r)
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
                BigSize(*self as u64).consensus_encode(writer)
            }
        }

        impl Decodable for $num_type {
            fn consensus_decode<D: std::io::Read>(
                d: &mut D,
                _modules: &ModuleDecoderRegistry,
            ) -> Result<Self, crate::encoding::DecodeError> {
                let varint = BigSize::consensus_decode(d, &Default::default())
                    .map_err(crate::encoding::DecodeError::from_err)?;
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

impl<T> Encodable for &[T]
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += (self.len() as u64).consensus_encode(writer)?;
        for item in self.iter() {
            len += item.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<T> Encodable for Vec<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        (self as &[T]).consensus_encode(writer)
    }
}

impl<T> Decodable for Vec<T>
where
    T: Decodable,
{
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let len = u64::consensus_decode(d, modules)?;

        // `collect` under the hood uses `FromIter::from_iter`, which can potentially be
        // backed by code like:
        // <https://github.com/rust-lang/rust/blob/fe03b46ee4688a99d7155b4f9dcd875b6903952d/library/alloc/src/vec/spec_from_iter_nested.rs#L31>
        // This can take `size_hint` from input iterator and pre-allocate memory
        // upfront with `Vec::with_capacity`. Because of that untrusted `len`
        // should not be used directly.
        let cap_len = cmp::min(8_000 / mem::size_of::<T>() as u64, len);

        // Up to a cap, use the (potentially specialized for better perf in stdlib)
        // `from_iter`.
        let mut v: Vec<_> = (0..cap_len)
            .map(|_| T::consensus_decode(d, modules))
            .collect::<Result<Vec<_>, DecodeError>>()?;

        // Add any excess manually avoiding any surprises.
        while (v.len() as u64) < len {
            v.push(T::consensus_decode(d, modules)?);
        }

        assert_eq!(v.len() as u64, len);

        Ok(v)
    }
}

#[test]
fn vec_decode_sanity() {
    let buf = [
        0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // On malicious large len, return an error instead of panicking.
    // Note: This was supposed to expose the panic, but I was not able to trigger it
    // for some reason.
    assert!(Vec::<u8>::consensus_decode(&mut buf.as_slice(), &Default::default()).is_err());
    assert!(Vec::<u16>::consensus_decode(&mut buf.as_slice(), &Default::default()).is_err());
}

impl<T, const SIZE: usize> Encodable for [T; SIZE]
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        for item in self.iter() {
            len += item.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<T, const SIZE: usize> Decodable for [T; SIZE]
where
    T: Decodable + Debug + Default + Copy,
{
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        // todo: impl without copy
        let mut data = [T::default(); SIZE];
        for item in data.iter_mut() {
            *item = T::consensus_decode(d, modules)?;
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
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let flag = u8::consensus_decode(d, modules)?;
        match flag {
            0 => Ok(None),
            1 => Ok(Some(T::consensus_decode(d, modules)?)),
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
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Box::new(T::consensus_decode(d, modules)?))
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
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        String::from_utf8(Decodable::consensus_decode(d, modules)?).map_err(DecodeError::from_err)
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
        Ok(Duration::new(secs, nsecs))
    }
}

impl Encodable for lightning_invoice::Invoice {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_string().consensus_encode(writer)
    }
}

impl Encodable for lightning::routing::gossip::RoutingFees {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.base_msat.consensus_encode(writer)?;
        len += self.proportional_millionths.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for lightning::routing::gossip::RoutingFees {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let base_msat = Decodable::consensus_decode(d, modules)?;
        let proportional_millionths = Decodable::consensus_decode(d, modules)?;
        Ok(lightning::routing::gossip::RoutingFees {
            base_msat,
            proportional_millionths,
        })
    }
}

impl Decodable for lightning_invoice::Invoice {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        String::consensus_decode(d, modules)?
            .parse::<lightning_invoice::Invoice>()
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

        DecodeError(anyhow::Error::from(StrError(s)))
    }

    pub fn from_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        DecodeError(anyhow::Error::from(e))
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
        for (k, v) in self.iter() {
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
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut res = BTreeMap::new();
        let len = u64::consensus_decode(d, modules)?;
        for _ in 0..len {
            let amt = K::consensus_decode(d, modules)?;
            let v = V::consensus_decode(d, modules)?;
            if res.insert(amt, v).is_some() {
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
        for k in self.iter() {
            len += k.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<K> Decodable for BTreeSet<K>
where
    K: Decodable + Ord,
{
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut res = BTreeSet::new();
        let len = u64::consensus_decode(d, modules)?;
        for _ in 0..len {
            let k = K::consensus_decode(d, modules)?;
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
    /// Returns the number of bytes successfull written so far
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

impl<W: Write> Write for CountWrite<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.count += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::io::Cursor;

    use bitcoin_hashes::hex::FromHex;

    use super::*;
    use crate::db::DatabaseValue;
    use crate::encoding::{Decodable, Encodable};
    use crate::ModuleDecoderRegistry;

    pub(crate) fn test_roundtrip<T>(value: T)
    where
        T: Encodable + Decodable + Eq + Debug,
    {
        let mut bytes = Vec::new();
        let len = value.consensus_encode(&mut bytes).unwrap();
        assert_eq!(len, bytes.len());

        let mut cursor = Cursor::new(bytes);
        let decoded = T::consensus_decode(&mut cursor, &ModuleDecoderRegistry::default()).unwrap();
        assert_eq!(value, decoded);
        assert_eq!(cursor.position(), len as u64);
    }

    pub(crate) fn test_roundtrip_expected<T>(value: T, expected: &[u8])
    where
        T: Encodable + Decodable + Eq + Debug,
    {
        let mut bytes = Vec::new();
        let len = value.consensus_encode(&mut bytes).unwrap();
        assert_eq!(len, bytes.len());
        assert_eq!(&expected, &bytes);

        let mut cursor = Cursor::new(bytes);
        let decoded = T::consensus_decode(&mut cursor, &ModuleDecoderRegistry::default()).unwrap();
        assert_eq!(value, decoded);
        assert_eq!(cursor.position(), len as u64);
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

        test_roundtrip_expected(reference, &bytes);
    }

    #[test_log::test]
    fn test_derive_tuple_struct() {
        #[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
        struct TestStruct(Vec<u8>, u32);

        let reference = TestStruct(vec![1, 2, 3], 42);
        let bytes = [3, 1, 2, 3, 42];

        test_roundtrip_expected(reference, &bytes);
    }

    #[test_log::test]
    fn test_derive_enum() {
        #[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
        enum TestEnum {
            Foo(Option<u64>),
            Bar { bazz: Vec<u8> },
        }

        let test_cases = [
            (TestEnum::Foo(Some(42)), vec![0, 1, 42]),
            (TestEnum::Foo(None), vec![0, 0]),
            (
                TestEnum::Bar {
                    bazz: vec![1, 2, 3],
                },
                vec![1, 3, 1, 2, 3],
            ),
        ];

        for (reference, bytes) in test_cases {
            test_roundtrip_expected(reference, &bytes);
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
        let invoice = invoice_str.parse::<lightning_invoice::Invoice>().unwrap();
        test_roundtrip(invoice);
    }

    #[test_log::test]
    fn test_btreemap() {
        test_roundtrip(BTreeMap::from([
            ("a".to_string(), 1u32),
            ("b".to_string(), 2),
        ]));
    }

    #[test_log::test]
    fn test_btreeset() {
        test_roundtrip(BTreeSet::from(["a".to_string(), "b".to_string()]));
    }

    #[test_log::test]
    fn test_systemtime() {
        test_roundtrip(fedimint_core::time::now());
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
        let amounts = (0..20000).map(TestAmount).collect::<Vec<_>>();
        keeps_ordering_after_serialization(amounts);

        #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Encodable, Decodable)]
        struct TestComplexAmount(u16, u32, u64);
        let complex_amounts = (10..20000)
            .flat_map(|i| {
                (i - 1..=i + 1).flat_map(move |j| {
                    (i - 1..=i + 1).map(move |k| TestComplexAmount(i as u16, j as u32, k as u64))
                })
            })
            .collect::<Vec<_>>();
        keeps_ordering_after_serialization(complex_amounts);

        #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Encodable, Decodable)]
        struct Text(String);
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
        let txid = bitcoin::Txid::from_hex(
            "51f7ed2f23e58cc6e139e715e9ce304a1e858416edc9079dd7b74fa8d2efc09a",
        )
        .unwrap();
        test_roundtrip_expected(
            txid,
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
            transaction,
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
        let blockhash = bitcoin::BlockHash::from_hex(
            "0000000000000000000065bda8f8a88f2e1e00d9a6887a43d640e52a4c7660f2",
        )
        .unwrap();
        test_roundtrip_expected(
            blockhash,
            &[
                242, 96, 118, 76, 42, 229, 64, 214, 67, 122, 136, 166, 217, 0, 30, 46, 143, 168,
                248, 168, 189, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        );
    }
}
