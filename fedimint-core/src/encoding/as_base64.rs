use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize as _;

use super::{Decodable, Encodable};
use crate::module::registry::ModuleRegistry;

pub fn serialize<T, S>(t: &T, ser: S) -> Result<S::Ok, S::Error>
where
    T: Encodable,
    S: serde::Serializer,
{
    ser.serialize_str(&URL_SAFE_NO_PAD.encode(t.consensus_encode_to_vec()))
}

pub fn deserialize<'de, T: Decodable, D>(de: D) -> Result<T, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    Decodable::consensus_decode_whole(
        &URL_SAFE_NO_PAD
            .decode(&String::deserialize(de)?)
            .map_err(|e| {
                serde::de::Error::custom(format!("decodable deserialization failed: {e:#}"))
            })?,
        &ModuleRegistry::default(),
    )
    .map_err(|e| serde::de::Error::custom(format!("decodable deserialization failed: {e:#}")))
}
