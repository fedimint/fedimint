use bls12_381::Scalar;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(x: &Scalar, s: S) -> Result<S::Ok, S::Error> {
    let bytes = x.to_bytes();
    if s.is_human_readable() {
        s.serialize_str(&hex::encode(bytes))
    } else {
        s.serialize_bytes(&bytes)
    }
}

pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Scalar, D::Error> {
    let bytes: Vec<u8> = if d.is_human_readable() {
        hex::decode::<String>(Deserialize::deserialize(d)?).map_err(serde::de::Error::custom)?
    } else {
        Deserialize::deserialize(d)?
    };
    if bytes.len() != 32 {
        return Err(D::Error::invalid_length(bytes.len(), &"32 bytes"));
    }
    let mut byte_array = [0u8; 32];
    byte_array.copy_from_slice(&bytes);

    let scalar = Scalar::from_bytes(&byte_array);
    // FIXME: probably safe with public data, but doesn't look nice
    if scalar.is_some().into() {
        Ok(scalar.unwrap())
    } else {
        Err(D::Error::custom("Could not decode compressed G1Affine"))
    }
}
