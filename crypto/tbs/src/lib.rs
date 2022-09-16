//! # Threshold Blind Signatures
//!
//! This library implements an ad-hoc threshold blind signature scheme based on BLS signatures using
//! the (unrelated) BLS12-381 curve.

use crate::hash::{hash_bytes_to_curve, hash_to_curve};
use crate::poly::Poly;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective};
use ff::Field;
use group::Curve;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::digest::generic_array::typenum::U32;
use sha3::Digest;
use std::hash::Hasher;

pub use bls12_381::G1Affine as MessagePoint;
pub use bls12_381::G2Affine as PubKeyPoint;
pub use bls12_381::Scalar;

pub mod hash;
pub mod poly;
mod serde_impl;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyShare(#[serde(with = "serde_impl::g2")] pub G2Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretKeyShare(#[serde(with = "serde_impl::scalar")] pub Scalar);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AggregatePublicKey(#[serde(with = "serde_impl::g2")] pub G2Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlindingKey(#[serde(with = "serde_impl::scalar")] pub Scalar);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct BlindedMessage(#[serde(with = "serde_impl::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct BlindedSignatureShare(#[serde(with = "serde_impl::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct BlindedSignature(#[serde(with = "serde_impl::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "serde_impl::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Message(#[serde(with = "serde_impl::g1")] pub G1Affine);

pub trait FromRandom {
    fn from_random(rng: &mut impl RngCore) -> Self;
}

impl FromRandom for Scalar {
    fn from_random(rng: &mut impl RngCore) -> Self {
        Field::random(rng)
    }
}

impl Message {
    pub fn from_bytes(msg: &[u8]) -> Message {
        Message(hash_bytes_to_curve::<G1Projective>(msg).to_affine())
    }

    /// **IMPORTANT**: `from_bytes` includes a tag in the hash, this doesn't
    pub fn from_hash(hash: impl Digest<OutputSize = U32>) -> Message {
        Message(hash_to_curve::<G1Projective, _>(hash).to_affine())
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for AggregatePublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let serialized = self.0.to_compressed();
        state.write(&serialized);
    }
}

macro_rules! point_impl {
    ($type:ty) => {
        impl std::hash::Hash for $type {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                let serialized = self.0.to_compressed();
                state.write(&serialized);
            }
        }

        impl $type {
            pub fn encode_compressed(&self) -> [u8; 48] {
                self.0.to_compressed()
            }
        }

        impl PartialEq for $type {
            fn eq(&self, other: &$type) -> bool {
                self.0 == other.0
            }
        }

        impl Eq for $type {}
    };
}

point_impl!(BlindedMessage);
point_impl!(Message);
point_impl!(Signature);
point_impl!(BlindedSignature);
point_impl!(BlindedSignatureShare);

impl SecretKeyShare {
    pub fn to_pub_key_share(self) -> PublicKeyShare {
        PublicKeyShare((G2Projective::generator() * self.0).to_affine())
    }
}

impl BlindingKey {
    pub fn random() -> BlindingKey {
        // TODO: fix rand incompatibities
        BlindingKey(Scalar::random(OsRng))
    }
}

/// * `threshold`: how many signature shares are needed to produce a signature
/// * `keys`: how many keys to generate
pub fn dealer_keygen(
    threshold: usize,
    keys: usize,
) -> (AggregatePublicKey, Vec<PublicKeyShare>, Vec<SecretKeyShare>) {
    let mut rng = OsRng; // FIXME: pass rng
    let poly = Poly::<Scalar, Scalar>::random(threshold - 1, &mut rng);
    let (pub_shares, sec_shares) = (1..=keys)
        .map(|idx| {
            let sk = poly.evaluate(idx as u64);
            let pk = G2Projective::generator() * sk;

            (PublicKeyShare(pk.to_affine()), SecretKeyShare(sk))
        })
        .unzip();
    let pub_key = G2Projective::generator() * poly.evaluate(0);

    (
        AggregatePublicKey(pub_key.to_affine()),
        pub_shares,
        sec_shares,
    )
}

pub fn blind_message(msg: Message) -> (BlindingKey, BlindedMessage) {
    let mut rng = OsRng;
    let blinding_key = Scalar::random(&mut rng);
    let blinded_msg = msg.0 * blinding_key;

    (
        BlindingKey(blinding_key),
        BlindedMessage(blinded_msg.to_affine()),
    )
}

pub fn sign_blinded_msg(msg: BlindedMessage, sks: SecretKeyShare) -> BlindedSignatureShare {
    let sig = msg.0 * sks.0;
    BlindedSignatureShare(sig.to_affine())
}

/// Combines a sufficent amount of valid blinded signature shares to a blinded signature. The
/// responsibility of verifying the supplied shares lies with the caller.
///
/// * `sig_shares`: an iterator yielding pairs of key indices and signature shares from said key
/// * `threshold`: number of shares needed to combine a signature
///
/// # Panics
/// If the amount of shares supplied is less than the necessary amount
pub fn combine_valid_shares<I>(sig_shares: I, threshold: usize) -> BlindedSignature
where
    I: IntoIterator<Item = (usize, BlindedSignatureShare)>,
    I::IntoIter: Clone + ExactSizeIterator,
{
    let points = sig_shares
        .into_iter()
        .take(threshold)
        .map(|(idx, share)| {
            let x = Scalar::from((idx as u64) + 1);
            let y = share.0.into();
            (x, y)
        })
        .collect::<Vec<(Scalar, G1Projective)>>();
    if points.len() < threshold {
        panic!("Not enough signature shares");
    }

    if points.len() == 1 {
        return BlindedSignature(points.first().unwrap().1.to_affine());
    }

    let bsig: G1Projective = poly::interpolate_zero(points.into_iter());
    BlindedSignature(bsig.to_affine())
}

pub fn unblind_signature(blinding_key: BlindingKey, blinded_sig: BlindedSignature) -> Signature {
    let sig = blinded_sig.0 * blinding_key.0.invert().unwrap();
    Signature(sig.to_affine())
}

pub fn verify(msg: Message, sig: Signature, pk: AggregatePublicKey) -> bool {
    pairing(&msg.0, &pk.0) == pairing(&sig.0, &G2Affine::generator())
}

pub fn verify_blind_share(
    msg: BlindedMessage,
    sig: BlindedSignatureShare,
    pk: PublicKeyShare,
) -> bool {
    pairing(&msg.0, &pk.0) == pairing(&sig.0, &G2Affine::generator())
}

pub trait Aggregatable {
    type Aggregate;

    fn aggregate(&self, threshold: usize) -> Self::Aggregate;
}

impl Aggregatable for Vec<PublicKeyShare> {
    type Aggregate = AggregatePublicKey;

    fn aggregate(&self, threshold: usize) -> Self::Aggregate {
        if self.len() == 1 {
            return AggregatePublicKey(self.first().unwrap().0);
        }

        let elements = self
            .iter()
            .enumerate()
            .map(|(idx, PublicKeyShare(pk))| (Scalar::from((idx + 1) as u64), pk.into()))
            .take(threshold);
        let pk: G2Projective = poly::interpolate_zero(elements);
        AggregatePublicKey(pk.to_affine())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        blind_message, combine_valid_shares, dealer_keygen, sign_blinded_msg, unblind_signature,
        verify, Aggregatable, Message,
    };

    #[test]
    fn test_keygen() {
        let (pk, pks, _sks) = dealer_keygen(5, 15);
        assert_eq!(pks.len(), 15);

        let pka = pks.aggregate(5);
        assert_eq!(pka, pk);
    }

    #[test]
    fn test_roundtrip() {
        let msg = Message::from_bytes(b"Hello World!");
        let threshold = 5;

        let (bkey, bmsg) = blind_message(msg);

        let (pk, _pks, sks) = dealer_keygen(threshold, 15);

        let mut sigs = sks
            .iter()
            .enumerate()
            .map(|(idx, sk)| (idx, sign_blinded_msg(bmsg, *sk)))
            .collect::<Vec<_>>();

        // All sig shards available
        let bsig = combine_valid_shares(sigs.clone().into_iter(), threshold);
        let sig = unblind_signature(bkey, bsig);
        assert!(verify(msg, sig, pk));

        // Missing sig shards
        for _ in 0..5 {
            sigs.pop();
        }
        let bsig = combine_valid_shares(sigs.clone().into_iter(), threshold);
        let sig = unblind_signature(bkey, bsig);
        assert!(verify(msg, sig, pk));

        let new_order = [9, 5, 4, 7, 8, 6, 0, 1, 3, 2];

        let shuffle_sigs = new_order.iter().map(|idx| sigs[*idx]);
        let bsig = combine_valid_shares(shuffle_sigs, threshold);
        let sig = unblind_signature(bkey, bsig);
        assert!(verify(msg, sig, pk));
    }

    #[test]
    #[should_panic(expected = "Not enough signature shares")]
    fn test_insufficient_shares() {
        let msg = Message::from_bytes(b"Hello World!");
        let threshold = 5;

        let (_, bmsg) = blind_message(msg);

        let (_, _pks, sks) = dealer_keygen(threshold, 4);

        let sigs = sks
            .iter()
            .enumerate()
            .map(|(idx, sk)| (idx, sign_blinded_msg(bmsg, *sk)));

        // Combining an insufficient number of signature shares should panic
        combine_valid_shares(sigs, threshold);
    }
}
