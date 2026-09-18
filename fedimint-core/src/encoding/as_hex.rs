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
use crate::module::registry::ModuleRegistry;

pub fn serialize<T, S>(t: &T, ser: S) -> Result<S::Ok, S::Error>
where
    T: Encodable,
    S: serde::Serializer,
{
    ser.serialize_str(&t.consensus_encode_to_hex())
}

pub fn deserialize<'de, T: Decodable, D>(de: D) -> Result<T, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    Decodable::consensus_decode_hex(&String::deserialize(de)?, &ModuleRegistry::default()).map_err(
        |e| {
            serde::de::Error::custom(format!(
                "decodable deserialization failed: {}",
                crate::util::FmtCompact::fmt_compact(&e)
            ))
        },
    )
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
                    serde::ser::Error::custom(format!("encodable serialization failed: {e:#}"))
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
                    serde::de::Error::custom(format!(
                        "decodable deserialization failed: {}",
                        $crate::util::FmtCompact::fmt_compact(&e)
                    ))
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

#[cfg(test)]
mod tests {
    use fedimint_derive::{Decodable, Encodable};

    use crate::encoding::Decodable as _;
    use crate::module::registry::ModuleRegistry;
    use crate::util::FmtCompact as _;

    #[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
    struct TestStruct {
        vec: Vec<u8>,
        num: u32,
    }

    #[derive(Debug, serde::Deserialize)]
    struct Wrapper {
        #[serde(with = "crate::encoding::as_hex", rename = "inner")]
        _inner: TestStruct,
    }

    #[test_log::test]
    fn deserialize_reports_the_whole_decode_chain() {
        // `vec` decodes as one element (7); `num` then has no bytes left, so this
        // fails deep inside the derived decoder, not at the hex-parsing layer.
        let err = serde_json::from_str::<Wrapper>(r#"{"inner":"0107"}"#)
            .expect_err("payload is truncated");

        let expected = TestStruct::consensus_decode_hex("0107", &ModuleRegistry::default())
            .expect_err("payload is truncated");

        assert!(
            err.to_string().starts_with(&format!(
                "decodable deserialization failed: {}",
                expected.fmt_compact()
            )),
            "{err}"
        );
        assert_ne!(
            expected.fmt_compact().to_string(),
            expected.to_string(),
            "the decode error has more than one layer and the message shows all of them"
        );
    }
}
