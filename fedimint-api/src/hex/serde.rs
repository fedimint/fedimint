use std::borrow::Cow;

use bitcoin_hashes::hex::{FromHex, ToHex};
use serde::de::Error;
use serde::{Deserialize, Serializer};

/// Serialize a `&[u8]` to a hex String
pub fn serialize<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex: String = data.to_hex();
    serializer.serialize_str(&hex)
}

/// Deserialize a hex String to a `Vec<u8>`
pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let hex_bytes: Cow<'de, str> = Deserialize::deserialize(d)?;
    Vec::from_hex(hex_bytes.as_ref()).map_err(|_| D::Error::custom("invalid hex"))
}

mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Data {
        #[serde(with = "fedimint_api::hex::serde")]
        inner: Vec<u8>,
    }

    #[test]
    fn hex_serialize() {
        let data = Data {
            inner: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };
        let json = serde_json::to_string(&data).unwrap();

        assert_eq!(json, r#"{"inner":"000102030405060708090a0b0c0d0e0f10"}"#);
    }

    #[test]
    fn hex_deserialize() {
        let json = r#"{"inner":"000102030405060708090a0b0c0d0e0f10"}"#;
        let data: Data = serde_json::from_str(json).unwrap();

        assert_eq!(
            data,
            Data {
                inner: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
            }
        );
    }
}
