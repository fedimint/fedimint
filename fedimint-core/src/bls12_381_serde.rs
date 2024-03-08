pub mod scalar {
    use bitcoin_hashes::hex::{FromHex, ToHex};
    use bls12_381::Scalar;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(x: &Scalar, s: S) -> Result<S::Ok, S::Error> {
        let bytes = x.to_bytes();

        if s.is_human_readable() {
            s.serialize_str(&bytes.to_hex())
        } else {
            s.serialize_bytes(&bytes)
        }
    }

    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Scalar, D::Error> {
        let bytes: Vec<u8> = if d.is_human_readable() {
            let deser: String = Deserialize::deserialize(d)?;
            Vec::<u8>::from_hex(&deser).map_err(serde::de::Error::custom)?
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
}

macro_rules! impl_serde_g {
    ($g:ty, $len:expr) => {
        use bitcoin_hashes::hex::{FromHex, ToHex};
        use serde::de::Error;
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(g: &$g, s: S) -> Result<S::Ok, S::Error> {
            let bytes = g.to_compressed();
            if s.is_human_readable() {
                s.serialize_str(&bytes.to_hex().as_ref())
            } else {
                s.serialize_bytes(&bytes)
            }
        }

        pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<$g, D::Error> {
            let bytes: Vec<u8> = if d.is_human_readable() {
                let deser: String = Deserialize::deserialize(d)?;
                Vec::<u8>::from_hex(&deser).map_err(serde::de::Error::custom)?
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
