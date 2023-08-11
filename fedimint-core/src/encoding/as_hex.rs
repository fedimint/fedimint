//! Serde implementations using hex-encoded encodables
//!
//! Oftentimes it's convenient to de/serialize consensus encodable data
//! as using consensus encoding (wrapped in hex encoding).
//!
//! If you have just a field use just:
//!
//! ```norust
//! #[serde(with = "::fedimint_core::encoding::as_hex")] EncodableType,
//! ```
//!
//! If you want to do it for the whole `struct`, use
//! [`crate::serde_as_encodable_hex`] macro.

use serde::Deserialize;

use super::{Decodable, Encodable};

pub fn serialize<T, S>(t: &T, ser: S) -> Result<S::Ok, S::Error>
where
    T: Encodable,
    S: serde::Serializer,
{
    ser.serialize_str(
        &t.consensus_encode_to_hex().map_err(|e| {
            serde::ser::Error::custom(format!("encodable serialization failed: {e:?}"))
        })?,
    )
}

pub fn deserialize<'de, T: Decodable, D>(de: D) -> Result<T, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    Decodable::consensus_decode_hex(&String::deserialize(de)?, &Default::default())
        .map_err(|e| serde::de::Error::custom(format!("decodable deserialization failed: {e:?}")))
}

#[macro_export]
macro_rules! serialize_as_encodable_hex {
    ($name:ident) => {
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use $crate::Encodable;
                serializer.serialize_str(&self.consensus_encode_to_hex().map_err(|e| {
                    serde::ser::Error::custom(format!("encodable serialization failed: {e:?}"))
                })?)
            }
        }
    };
}

#[macro_export]
macro_rules! deserialize_as_encodable_hex {
    ($name:ident) => {
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                $crate::Decodable::consensus_decode_hex(
                    &String::deserialize(deserializer)?,
                    &Default::default(),
                )
                .map_err(|e| {
                    serde::de::Error::custom(format!("decodable deserialization failed: {e:?}"))
                })
            }
        }
    };
}

#[macro_export]
macro_rules! serde_as_encodable_hex {
    ($name:ident) => {
        $crate::serialize_as_encodable_hex!($name);
        $crate::deserialize_as_encodable_hex!($name);
    };
}
