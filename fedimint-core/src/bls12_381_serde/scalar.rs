use bls12_381::Scalar;
use serde::de::Error;
use serde::{Deserializer, Serializer};

pub fn serialize<S: Serializer>(scalar: &Scalar, s: S) -> Result<S::Ok, S::Error> {
    serdect::array::serialize_hex_lower_or_bin(&scalar.to_bytes(), s)
}

pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Scalar, D::Error> {
    let mut byte_array = [0; 32];

    serdect::array::deserialize_hex_or_bin(&mut byte_array, d)?;

    Option::from(Scalar::from_bytes(&byte_array))
        .ok_or_else(|| Error::custom("Could not decode scalar"))
}
