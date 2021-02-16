pub mod scalar;

macro_rules! impl_serde_g {
    ($g:ty, $len:expr) => {
        use serde::de::Error;
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(g: &$g, s: S) -> Result<S::Ok, S::Error> {
            let bytes = g.to_compressed();
            if s.is_human_readable() {
                s.serialize_str(&hex::encode(&bytes))
            } else {
                s.serialize_bytes(&bytes)
            }
        }

        pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<$g, D::Error> {
            let bytes: Vec<u8> = if d.is_human_readable() {
                hex::decode::<String>(Deserialize::deserialize(d)?)
                    .map_err(serde::de::Error::custom)?
            } else {
                Deserialize::deserialize(d)?
            };

            if bytes.len() != $len {
                return Err(D::Error::invalid_length(bytes.len(), &"48 bytes"));
            }
            let mut byte_array = [0u8; $len];
            byte_array.copy_from_slice(&bytes);

            let g = <$g>::from_compressed(&byte_array);
            if g.is_some().into() {
                Ok(g.unwrap())
            } else {
                Err(D::Error::custom(
                    "Could not decode compressed group element",
                ))
            }
        }
    };
}

pub mod g1 {
    impl_serde_g!(bls12_381::G1Affine, 48);
}

pub mod g2 {
    impl_serde_g!(bls12_381::G2Affine, 96);
}
