//! # THIS IS NOT MuSig
//!
//! This module is a ad-hoc signature aggregation scheme to be replaced with MuSig2 once an
//! implementation is available.

use secp256kfun::marker::{ChangeMark, NonZero, Normal, Public, Secret};
use secp256kfun::op::{point_add, scalar_add, scalar_mul};
use secp256kfun::rand_core::{CryptoRng, RngCore};
use secp256kfun::{g, Point, Scalar, G};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256 as Sha256;
use std::convert::TryInto;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PubKey(Point);

#[derive(Clone, Debug, PartialEq, Hash, Serialize, Deserialize)]
pub struct Sig {
    r: Point,
    s: Scalar<Public>,
}

impl Eq for Sig {} // FIXME: check why it doesn't work otherwise

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecKey(Scalar);

impl SecKey {
    pub fn random(mut rng: impl RngCore + CryptoRng) -> SecKey {
        SecKey(Scalar::random(&mut rng))
    }

    pub fn to_public(&self) -> PubKey {
        let p = Normal::change_mark(g!({ &self.0 } * G));
        PubKey(p)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Option<SecKey> {
        Some(SecKey(NonZero::change_mark(Scalar::from_bytes(bytes)?)?))
    }
}

impl Sig {
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..33].copy_from_slice(&self.r.to_bytes());
        bytes[33..65].copy_from_slice(&self.s.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: [u8; 65]) -> Option<Self> {
        let r = Point::from_bytes(bytes[0..33].try_into().unwrap())?;
        let s = Public::change_mark(
            NonZero::change_mark(
                Scalar::from_bytes(bytes[33..65].try_into().unwrap()).expect("from bytes error"),
            )
            .expect("zero error"),
        );

        Some(Sig { r, s })
    }
}

pub fn sign<'a>(
    msg: [u8; 32],
    secret_keys: impl Iterator<Item = &'a SecKey> + Clone,
    mut rng: impl RngCore + CryptoRng,
) -> Sig {
    let msg_hash = NonZero::change_mark(Scalar::from_bytes_mod_order(msg)).unwrap();

    let pub_keys = secret_keys
        .clone()
        .map(SecKey::to_public)
        .collect::<Vec<_>>();

    let r_sec = Scalar::random(&mut rng);
    let r_pub = Normal::change_mark(g!(r_sec * G));

    let s = scalar_add(
        &secret_keys
            .map(|sk| {
                let pk = Normal::change_mark(g!({ &sk.0 } * G));

                let c = {
                    let mut c_hasher = Sha256::default();
                    bincode::serialize_into(&mut c_hasher, &pk).unwrap();
                    bincode::serialize_into(&mut c_hasher, &r_pub).unwrap();
                    bincode::serialize_into(&mut c_hasher, &pub_keys).unwrap();
                    bincode::serialize_into(&mut c_hasher, &msg_hash).unwrap();
                    Scalar::from_hash(c_hasher)
                };

                scalar_mul(&scalar_mul(&sk.0, &c), &msg_hash)
            })
            .reduce(|a, b| {
                NonZero::change_mark(scalar_add::<NonZero, NonZero, Secret, Secret>(&a, &b))
                    .unwrap()
            })
            .unwrap(),
        &r_sec,
    );
    let non_zero_s = NonZero::change_mark(s).unwrap();
    let public_s = Public::change_mark(non_zero_s);

    Sig {
        r: r_pub,
        s: public_s,
    }
}

pub fn verify(msg: [u8; 32], sig: Sig, pks: &[&PubKey]) -> bool {
    let msg_hash = Scalar::from_bytes_mod_order(msg);
    let Sig { r, s } = sig;

    let pk_msg_sum = pks
        .iter()
        .map(|&pk| {
            let c = {
                let mut c_hasher = Sha256::default();
                bincode::serialize_into(&mut c_hasher, &pk).unwrap();
                bincode::serialize_into(&mut c_hasher, &r).unwrap();
                bincode::serialize_into(&mut c_hasher, &pks).unwrap();
                bincode::serialize_into(&mut c_hasher, &msg_hash).unwrap();
                Scalar::from_hash(c_hasher)
            };

            g!(c * (msg_hash * { &pk.0 }))
        })
        .fold(r, |a, b| {
            Normal::change_mark(NonZero::change_mark(point_add(&a, &b)).unwrap())
        });

    let sg = Normal::change_mark(g!(s * G));
    sg == pk_msg_sum
}

impl PubKey {
    pub fn to_bytes(&self) -> [u8; 33] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 33]) -> Option<PubKey> {
        Point::from_bytes(bytes).map(PubKey)
    }
}

pub mod rng_adapt {
    use secp256kfun::rand_core::Error;

    pub struct RngAdaptor<R>(pub R);

    impl<R: rand::CryptoRng> secp256kfun::rand_core::CryptoRng for RngAdaptor<R> {}

    impl<R: rand::RngCore> secp256kfun::rand_core::RngCore for RngAdaptor<R> {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.0
                .try_fill_bytes(dest)
                .map_err(secp256kfun::rand_core::Error::new)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rng_adapt::RngAdaptor;
    use crate::{sign, verify, SecKey};
    use sha3::{Digest, Sha3_256};
    use std::io::Write;

    #[test]
    fn round_trip() {
        let mut rng = RngAdaptor(rand::rngs::OsRng::new().unwrap());
        let secrets = (0..10)
            .map(|_| SecKey::random(&mut rng))
            .collect::<Vec<_>>();
        let pks = secrets.iter().map(SecKey::to_public).collect::<Vec<_>>();

        let msg = b"Hello World!";
        let mut digest = Sha3_256::new();
        digest.write_all(&msg[..]).unwrap();

        let hash = digest.finalize().into();

        let sig = sign(hash, secrets.iter(), rng);
        assert!(verify(hash, sig, &pks.iter().collect::<Vec<_>>()));
    }
}
