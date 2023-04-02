//! This module defines a binary encoding interface which is more suitable for
//! consensus critical encoding than e.g. `bincode`. Over time all structs that
//! need to be encoded to binary will be migrated to this interface.

mod btc;
mod secp256k1;
mod tbs;
mod tls;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};
use std::io::{self, Error, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::format_err;
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::sha256::HashEngine;
use bitcoin_hashes::{sha256, Hash};
pub use fedimint_derive::{Decodable, Encodable, UnzipConsensus};
use serde::{Deserialize, Serialize};
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

    /// Generate a SHA256 hash of the consensus encoding
    ///
    /// Can be used to validate all federation members agree on state without
    /// revealing the object
    fn consensus_hash(&self) -> anyhow::Result<sha256::Hash> {
        let mut engine = HashEngine::default();
        self.consensus_encode(&mut engine)?;
        Ok(sha256::Hash::from_engine(engine))
    }
}

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError>;
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

macro_rules! impl_encode_decode_num {
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

impl_encode_decode_num!(u64);
impl_encode_decode_num!(u32);
impl_encode_decode_num!(u16);
impl_encode_decode_num!(u8);

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
        (0..len).map(|_| T::consensus_decode(d, modules)).collect()
    }
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

/// A wrapper counting bytes written
struct CountWrite<'a, W> {
    inner: &'a mut W,
    count: usize,
}

impl<'a, W> CountWrite<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self { inner, count: 0 }
    }
}

impl<'a, W> io::Write for CountWrite<'a, W>
where
    W: io::Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(buf)?;
        self.count += count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
/// Wrappers for `T` that are `De-Serializable`, while we need them in
/// `Encodable` context
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize)]
pub struct SerdeEncodable<T>(pub T);

impl<T> Encodable for SerdeEncodable<T>
where
    T: serde::Serialize,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut count_writer = CountWrite::new(writer);
        bincode::serialize_into(&mut count_writer, &self.0)
            .map_err(|e| std::io::Error::new(io::ErrorKind::Other, e))?;
        Ok(count_writer.count)
    }
}

impl<T> Decodable for SerdeEncodable<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self(
            bincode::deserialize_from(r).map_err(|e| DecodeError(e.into()))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::io::Cursor;

    use super::*;
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
        let bytes = [3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 42, 0, 0, 0];

        test_roundtrip_expected(reference, &bytes);
    }

    #[test_log::test]
    fn test_derive_tuple_struct() {
        #[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
        struct TestStruct(Vec<u8>, u32);

        let reference = TestStruct(vec![1, 2, 3], 42);
        let bytes = [3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 42, 0, 0, 0];

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
            (
                TestEnum::Foo(Some(42)),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 1, 42, 0, 0, 0, 0, 0, 0, 0],
            ),
            (TestEnum::Foo(None), vec![0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (
                TestEnum::Bar {
                    bazz: vec![1, 2, 3],
                },
                vec![1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3],
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
    fn test_serde_encodable() {
        test_roundtrip(SerdeEncodable(6usize));
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
}
