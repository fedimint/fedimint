//! This module defines a binary encoding interface which is more suitable for consensus critical
//! encoding thant e.g. `bincode`. Over time all structs that need to be encoded to binary will
//! be migrated to this interface.

mod btc;
mod secp256k1;
mod tbs;

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::io::{Error, Read, Write};

pub use fedimint_derive::{Decodable, Encodable, UnzipConsensus};
use thiserror::Error;
use url::Url;

use crate::core::ModuleDecode;

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
}

// TODO: unify and/or make a newtype?
pub type ModuleKey = u16;

pub type ModuleRegistry<M> = BTreeMap<ModuleKey, M>;

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode<M, D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError>
    where
        M: ModuleDecode;
}

impl Encodable for Url {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_string().consensus_encode(writer)
    }
}

impl Decodable for Url {
    fn consensus_decode<M, D: std::io::Read>(
        d: &mut D,
        modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError>
    where
        M: ModuleDecode,
    {
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
                let bytes = self.to_le_bytes();
                writer.write_all(&bytes[..])?;
                Ok(bytes.len())
            }
        }

        impl Decodable for $num_type {
            fn consensus_decode<M, D: std::io::Read>(
                d: &mut D,
                _modules: &ModuleRegistry<M>,
            ) -> Result<Self, crate::encoding::DecodeError>
            where
                M: ModuleDecode,
            {
                let mut bytes = [0u8; (<$num_type>::BITS / 8) as usize];
                d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
                Ok(<$num_type>::from_le_bytes(bytes))
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
            fn consensus_decode<M, D: std::io::Read>(d: &mut D, modules: &ModuleRegistry<M>) -> Result<Self, DecodeError> where M : $crate::core::ModuleDecode {
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
    fn consensus_decode<M, D: std::io::Read>(
        d: &mut D,
        modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError>
    where
        M: ModuleDecode,
    {
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
    fn consensus_decode<M, D: std::io::Read>(
        d: &mut D,
        modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError>
    where
        M: ModuleDecode,
    {
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
    fn consensus_decode<M, D: std::io::Read>(
        d: &mut D,
        modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError>
    where
        M: ModuleDecode,
    {
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
    fn consensus_decode<M, D: std::io::Read>(
        d: &mut D,
        modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError>
    where
        M: ModuleDecode,
    {
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
    fn consensus_decode<M, D: std::io::Read>(
        _d: &mut D,
        _modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError>
    where
        M: ModuleDecode,
    {
        Ok(())
    }
}

impl Encodable for String {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.as_bytes().consensus_encode(writer)
    }
}

impl Decodable for String {
    fn consensus_decode<M, D: std::io::Read>(
        d: &mut D,
        modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError>
    where
        M: ModuleDecode,
    {
        String::from_utf8(Decodable::consensus_decode(d, modules)?).map_err(DecodeError::from_err)
    }
}

impl Encodable for lightning_invoice::Invoice {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_string().consensus_encode(writer)
    }
}

impl Decodable for lightning_invoice::Invoice {
    fn consensus_decode<M, D: std::io::Read>(
        d: &mut D,
        modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError>
    where
        M: ModuleDecode,
    {
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
    fn consensus_decode<M, D: Read>(
        d: &mut D,
        _modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError>
    where
        M: ModuleDecode,
    {
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::{collections::BTreeMap, fmt::Debug};

    use crate::encoding::{Decodable, Encodable};

    pub(crate) fn test_roundtrip<T>(value: T)
    where
        T: Encodable + Decodable + Eq + Debug,
    {
        let mut bytes = Vec::new();
        let len = value.consensus_encode(&mut bytes).unwrap();
        assert_eq!(len, bytes.len());

        let mut cursor = Cursor::new(bytes);
        let decoded = T::consensus_decode(&mut cursor, &BTreeMap::<_, ()>::new()).unwrap();
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
        let decoded = T::consensus_decode(&mut cursor, &BTreeMap::<_, ()>::new()).unwrap();
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
}
