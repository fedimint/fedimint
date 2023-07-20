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
