//! This module defines a binary encoding interface which is more suitable for consensus critical
//! encoding thant e.g. `bincode`. Over time all structs that need to be encoded to binary will
//! be migrated to this interface.

mod btc;
mod secp256k1;
mod tbs;

pub use minimint_derive::{Decodable, Encodable};
use std::fmt::{Debug, Formatter};
use std::io::Error;
use thiserror::Error;

/// Data which can be encoded in a consensus-consistent way
pub trait Encodable {
    /// Encode an object with a well-defined format.
    /// Returns the number of bytes written on success.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn consensus_encode<W: std::io::Write>(&self, writer: W) -> Result<usize, std::io::Error>;
}

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode<D: std::io::Read>(d: D) -> Result<Self, DecodeError>;
}

#[derive(Debug, Error)]
pub struct DecodeError(pub(crate) anyhow::Error);

macro_rules! impl_encode_decode_num {
    ($num_type:ty) => {
        impl Encodable for $num_type {
            fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, Error> {
                let bytes = self.to_le_bytes();
                writer.write_all(&bytes[..])?;
                Ok(bytes.len())
            }
        }

        impl Decodable for $num_type {
            fn consensus_decode<D: std::io::Read>(
                mut d: D,
            ) -> Result<Self, crate::encoding::DecodeError> {
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
            fn consensus_encode<W: std::io::Write>(&self, mut s: W) -> Result<usize, std::io::Error> {
                let &($(ref $x),*) = self;
                let mut len = 0;
                $(len += $x.consensus_encode(&mut s)?;)*
                Ok(len)
            }
        }

        #[allow(non_snake_case)]
        impl<$($x: Decodable),*> Decodable for ($($x),*) {
            fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
                Ok(($({let $x = Decodable::consensus_decode(&mut d)?; $x }),*))
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
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut len = 0;
        len += (self.len() as u64).consensus_encode(&mut writer)?;
        for item in self.iter() {
            len += item.consensus_encode(&mut writer)?;
        }
        Ok(len)
    }
}

impl<T> Encodable for Vec<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: W) -> Result<usize, Error> {
        (self as &[T]).consensus_encode(writer)
    }
}

impl<T> Decodable for Vec<T>
where
    T: Decodable,
{
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let len = u64::consensus_decode(&mut d)?;
        (0..len).map(|_| T::consensus_decode(&mut d)).collect()
    }
}

impl<T, const SIZE: usize> Encodable for [T; SIZE]
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        for item in self.iter() {
            len += item.consensus_encode(&mut writer)?;
        }
        Ok(len)
    }
}

impl<T, const SIZE: usize> Decodable for [T; SIZE]
where
    T: Decodable + Debug + Default + Copy,
{
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        // todo: impl without copy
        let mut data = [T::default(); SIZE];
        for item in data.iter_mut() {
            *item = T::consensus_decode(&mut d)?;
        }
        Ok(data)
    }
}

impl<T> Encodable for Option<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        if let Some(inner) = self {
            len += 1u8.consensus_encode(&mut writer)?;
            len += inner.consensus_encode(&mut writer)?;
        } else {
            len += 0u8.consensus_encode(&mut writer)?;
        }
        Ok(len)
    }
}

impl<T> Decodable for Option<T>
where
    T: Decodable,
{
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let flag = u8::consensus_decode(&mut d)?;
        match flag {
            0 => Ok(None),
            1 => Ok(Some(T::consensus_decode(&mut d)?)),
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
    fn consensus_encode<W: std::io::Write>(&self, writer: W) -> Result<usize, Error> {
        self.as_ref().consensus_encode(writer)
    }
}

impl<T> Decodable for Box<T>
where
    T: Decodable,
{
    fn consensus_decode<D: std::io::Read>(d: D) -> Result<Self, DecodeError> {
        Ok(Box::new(T::consensus_decode(d)?))
    }
}

impl Encodable for () {
    fn consensus_encode<W: std::io::Write>(&self, _writer: W) -> Result<usize, std::io::Error> {
        Ok(0)
    }
}

impl Decodable for () {
    fn consensus_decode<D: std::io::Read>(_d: D) -> Result<Self, DecodeError> {
        Ok(())
    }
}

impl Encodable for String {
    fn consensus_encode<W: std::io::Write>(&self, writer: W) -> Result<usize, Error> {
        self.as_bytes().consensus_encode(writer)
    }
}

impl Decodable for String {
    fn consensus_decode<D: std::io::Read>(d: D) -> Result<Self, DecodeError> {
        String::from_utf8(Decodable::consensus_decode(d)?).map_err(DecodeError::from_err)
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
    use crate::encoding::{Decodable, Encodable};
    use std::fmt::Debug;
    use std::io::Cursor;

    pub(crate) fn test_roundtrip<T>(value: T)
    where
        T: Encodable + Decodable + Eq + Debug,
    {
        let mut bytes = Vec::new();
        let len = value.consensus_encode(&mut bytes).unwrap();
        assert_eq!(len, bytes.len());

        let mut cursor = Cursor::new(bytes);
        let decoded = T::consensus_decode(&mut cursor).unwrap();
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
        let decoded = T::consensus_decode(&mut cursor).unwrap();
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
}
