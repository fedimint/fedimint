use bls12_381::G1Affine;
use serde::de::Error;
use serde::{Deserializer, Serializer};

pub fn serialize<S: Serializer>(point: &G1Affine, s: S) -> Result<S::Ok, S::Error> {
    serdect::array::serialize_hex_lower_or_bin(&point.to_compressed(), s)
}

pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<G1Affine, D::Error> {
    let mut byte_array = [0; 48];

    serdect::array::deserialize_hex_or_bin(&mut byte_array, d)?;

    Option::from(G1Affine::from_compressed(&byte_array))
        .ok_or_else(|| Error::custom("Could not decode compressed group element"))
}
