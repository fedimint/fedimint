//! # Threshold Blind Signatures
//!
//! This library implements an ad-hoc threshold blind signature scheme based on
//! BLS signatures using the (unrelated) BLS12-381 curve.

use std::collections::BTreeMap;

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective};
pub use bls12_381::{G1Affine as MessagePoint, G2Affine as PubKeyPoint, Scalar};
use ff::Field;
use group::{Curve, Group};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use sha3::Digest;

pub mod serde_impl;

const HASH_TAG: &[u8] = b"TBS_BLS12-381_";

fn hash_bytes_to_g1(data: &[u8]) -> G1Projective {
    let mut hash_engine = sha3::Sha3_256::new();

    hash_engine.update(HASH_TAG);
    hash_engine.update(data);

    let mut prng = ChaChaRng::from_seed(hash_engine.finalize().into());

    G1Projective::random(&mut prng)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretKeyShare(#[serde(with = "serde_impl::scalar")] pub Scalar);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyShare(#[serde(with = "serde_impl::g2")] pub G2Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AggregatePublicKey(#[serde(with = "serde_impl::g2")] pub G2Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Message(#[serde(with = "serde_impl::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlindingKey(#[serde(with = "serde_impl::scalar")] pub Scalar);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlindedMessage(#[serde(with = "serde_impl::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlindedSignatureShare(#[serde(with = "serde_impl::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlindedSignature(#[serde(with = "serde_impl::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "serde_impl::g1")] pub G1Affine);

macro_rules! point_hash_impl {
    ($type:ty) => {
        impl std::hash::Hash for $type {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                let serialized = self.0.to_compressed();
                state.write(&serialized);
            }
        }
    };
}

point_hash_impl!(PublicKeyShare);
point_hash_impl!(AggregatePublicKey);
point_hash_impl!(Message);
point_hash_impl!(BlindedMessage);
point_hash_impl!(BlindedSignatureShare);
point_hash_impl!(BlindedSignature);
point_hash_impl!(Signature);

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

impl Message {
    pub fn from_bytes(msg: &[u8]) -> Message {
        Message(hash_bytes_to_g1(msg).to_affine())
    }
}

pub fn blind_message(msg: Message, blinding_key: BlindingKey) -> BlindedMessage {
    let blinded_msg = msg.0 * blinding_key.0;

    BlindedMessage(blinded_msg.to_affine())
}

pub fn sign_blinded_msg(msg: BlindedMessage, sks: SecretKeyShare) -> BlindedSignatureShare {
    let sig = msg.0 * sks.0;
    BlindedSignatureShare(sig.to_affine())
}

pub fn verify_blind_share(
    msg: BlindedMessage,
    sig: BlindedSignatureShare,
    pk: PublicKeyShare,
) -> bool {
    pairing(&msg.0, &pk.0) == pairing(&sig.0, &G2Affine::generator())
}

/// Combines the exact threshold of valid blinded signature shares to a blinded
/// signature. The responsibility of verifying the shares and supplying
/// exactly the necessary threshold of shares lies with the caller.
/// # Panics
/// If shares is empty
pub fn aggregate_signature_shares(
    shares: &BTreeMap<u64, BlindedSignatureShare>,
) -> BlindedSignature {
    // this is a special case for one-of-one federations
    if shares.len() == 1 {
        return BlindedSignature(
            shares
                .values()
                .next()
                .expect("We have at least one value")
                .0,
        );
    }

    BlindedSignature(
        lagrange_multipliers(shares.keys().cloned().map(Scalar::from).collect())
            .into_iter()
            .zip(shares.values())
            .map(|(lagrange_multiplier, share)| lagrange_multiplier * share.0)
            .reduce(|a, b| a + b)
            .expect("We have at least one share")
            .to_affine(),
    )
}

// TODO: aggregating public key shares is hacky since we can obtain the
// aggregated public by evaluating the dkg polynomial at zero - this function
// should be removed, however it is currently needed in the mint module to
// until we add the aggregated public key to the mint config.
pub fn aggregate_public_key_shares(shares: &BTreeMap<u64, PublicKeyShare>) -> AggregatePublicKey {
    // this is a special case for one-of-one federations
    if shares.len() == 1 {
        return AggregatePublicKey(
            shares
                .values()
                .next()
                .expect("We have at least one value")
                .0,
        );
    }

    AggregatePublicKey(
        lagrange_multipliers(shares.keys().cloned().map(Scalar::from).collect())
            .into_iter()
            .zip(shares.values())
            .map(|(lagrange_multiplier, share)| lagrange_multiplier * share.0)
            .reduce(|a, b| a + b)
            .expect("We have at least one share")
            .to_affine(),
    )
}

fn lagrange_multipliers(scalars: Vec<Scalar>) -> Vec<Scalar> {
    scalars
        .iter()
        .map(|i| {
            scalars
                .iter()
                .filter(|j| *j != i)
                .map(|j| j * (j - i).invert().expect("We filtered the case j == i"))
                .reduce(|a, b| a * b)
                .expect("We have at least one share")
        })
        .collect()
}

pub fn unblind_signature(blinding_key: BlindingKey, blinded_sig: BlindedSignature) -> Signature {
    let sig = blinded_sig.0 * blinding_key.0.invert().unwrap();
    Signature(sig.to_affine())
}

pub fn verify(msg: Message, sig: Signature, pk: AggregatePublicKey) -> bool {
    pairing(&msg.0, &pk.0) == pairing(&sig.0, &G2Affine::generator())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bls12_381::{G2Projective, Scalar};
    use ff::Field;
    use group::Curve;
    use rand::rngs::OsRng;

    use crate::{
        aggregate_signature_shares, blind_message, sign_blinded_msg, unblind_signature, verify,
        verify_blind_share, AggregatePublicKey, BlindedSignatureShare, BlindingKey, Message,
        PublicKeyShare, SecretKeyShare,
    };

    fn dealer_keygen(
        threshold: usize,
        keys: usize,
    ) -> (AggregatePublicKey, Vec<PublicKeyShare>, Vec<SecretKeyShare>) {
        let mut rng = OsRng;
        let poly: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(&mut rng)).collect();

        let apk = (G2Projective::generator() * eval_polynomial(&poly, &Scalar::zero())).to_affine();

        let sks: Vec<SecretKeyShare> = (0..keys)
            .map(|idx| SecretKeyShare(eval_polynomial(&poly, &Scalar::from(idx as u64 + 1))))
            .collect();

        let pks = sks
            .iter()
            .map(|sk| PublicKeyShare((G2Projective::generator() * sk.0).to_affine()))
            .collect();

        (AggregatePublicKey(apk), pks, sks)
    }

    fn eval_polynomial(coefficients: &[Scalar], x: &Scalar) -> Scalar {
        coefficients
            .iter()
            .cloned()
            .rev()
            .reduce(|acc, coefficient| acc * x + coefficient)
            .expect("We have at least one coefficient")
    }

    #[test]
    fn test_roundtrip() {
        let (pk, pks, sks) = dealer_keygen(5, 15);

        let msg = Message::from_bytes(b"Hello World!");
        let bkey = BlindingKey::random();
        let bmsg = blind_message(msg, bkey);

        let bsig_shares = sks
            .iter()
            .map(|sk| sign_blinded_msg(bmsg, *sk))
            .collect::<Vec<BlindedSignatureShare>>();

        for (share, pk) in bsig_shares.iter().zip(pks) {
            assert!(verify_blind_share(bmsg, *share, pk));
        }

        let bsig_shares = (1_u64..)
            .zip(bsig_shares)
            .take(5)
            .collect::<BTreeMap<u64, BlindedSignatureShare>>();

        let bsig = aggregate_signature_shares(&bsig_shares);
        let sig = unblind_signature(bkey, bsig);

        assert!(verify(msg, sig, pk));
    }
}
