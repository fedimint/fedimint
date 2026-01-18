//! # Threshold Blind Signatures
//!
//! This library implements an ad-hoc threshold blind signature scheme based on
//! BLS signatures using the (unrelated) BLS12-381 curve.

use std::collections::BTreeMap;

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar, pairing};
use fedimint_core::bls12_381_serde;
use fedimint_core::encoding::{Decodable, Encodable};
use group::ff::Field;
use group::{Curve, Group};
use hex::encode;
use rand::SeedableRng;
use rand::rngs::OsRng;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use sha3::Digest;

const HASH_TAG: &[u8] = b"TBS_BLS12-381_";
const FINGERPRINT_TAG: &[u8] = b"TBS_KFP24_";

fn hash_bytes_to_g1(data: &[u8]) -> G1Projective {
    let mut hash_engine = sha3::Sha3_256::new();

    hash_engine.update(HASH_TAG);
    hash_engine.update(data);

    let mut prng = ChaChaRng::from_seed(hash_engine.finalize().into());

    G1Projective::random(&mut prng)
}

#[derive(Copy, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct SecretKeyShare(#[serde(with = "bls12_381_serde::scalar")] pub Scalar);

impl std::fmt::Debug for SecretKeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use sha3::Digest as _;
        if fedimint_core::fmt_utils::show_secrets() || f.alternate() {
            f.debug_tuple("SecretKeyShare")
                .field(&hex::encode(self.0.to_bytes()))
                .finish()
        } else {
            // Show fingerprint instead of actual secret
            let hash = sha3::Sha3_256::new()
                .chain_update(FINGERPRINT_TAG)
                .chain_update(self.0.to_bytes())
                .finalize();
            write!(f, "SecretKeyShare#<{}>", encode(&hash[..8]))
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct PublicKeyShare(#[serde(with = "bls12_381_serde::g2")] pub G2Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct AggregatePublicKey(#[serde(with = "bls12_381_serde::g2")] pub G2Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct Message(#[serde(with = "bls12_381_serde::g1")] pub G1Affine);

#[derive(Copy, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct BlindingKey(#[serde(with = "bls12_381_serde::scalar")] pub Scalar);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct BlindedMessage(#[serde(with = "bls12_381_serde::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct BlindedSignatureShare(#[serde(with = "bls12_381_serde::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct BlindedSignature(#[serde(with = "bls12_381_serde::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "bls12_381_serde::g1")] pub G1Affine);

macro_rules! point_hash_impl {
    ($type:ty) => {
        impl std::hash::Hash for $type {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.0.to_compressed().hash(state);
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

pub fn derive_pk_share(sk: &SecretKeyShare) -> PublicKeyShare {
    PublicKeyShare((G2Projective::generator() * sk.0).to_affine())
}

impl BlindingKey {
    pub fn random() -> BlindingKey {
        // TODO: fix rand incompatibities
        BlindingKey(Scalar::random(OsRng))
    }

    fn fingerprint(&self) -> [u8; 32] {
        let mut hash_engine = sha3::Sha3_256::new();
        hash_engine.update(FINGERPRINT_TAG);
        hash_engine.update(self.0.to_bytes());
        let result = hash_engine.finalize();
        result.into()
    }
}

impl ::core::fmt::Debug for BlindingKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        let fingerprint = self.fingerprint();
        let fingerprint_hex = encode(&fingerprint[..]);
        write!(f, "BlindingKey({fingerprint_hex})")
    }
}

impl ::core::fmt::Display for BlindingKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        let fingerprint = self.fingerprint();
        let fingerprint_hex = encode(&fingerprint[..]);
        write!(f, "{fingerprint_hex}")
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

pub fn sign_message(msg: BlindedMessage, sks: SecretKeyShare) -> BlindedSignatureShare {
    let sig = msg.0 * sks.0;
    BlindedSignatureShare(sig.to_affine())
}

pub fn verify_signature_share(
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
        lagrange_multipliers(
            shares
                .keys()
                .cloned()
                .map(|peer| Scalar::from(peer + 1))
                .collect(),
        )
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
        lagrange_multipliers(
            shares
                .keys()
                .cloned()
                .map(|peer| Scalar::from(peer + 1))
                .collect(),
        )
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

pub fn verify_blinded_signature(
    msg: BlindedMessage,
    sig: BlindedSignature,
    pk: AggregatePublicKey,
) -> bool {
    pairing(&msg.0, &pk.0) == pairing(&sig.0, &G2Affine::generator())
}

pub fn unblind_signature(blinding_key: BlindingKey, blinded_sig: BlindedSignature) -> Signature {
    let sig = blinded_sig.0 * blinding_key.0.invert().unwrap();
    Signature(sig.to_affine())
}

pub fn verify(msg: Message, sig: Signature, pk: AggregatePublicKey) -> bool {
    pairing(&msg.0, &pk.0) == pairing(&sig.0, &G2Affine::generator())
}

#[cfg(test)]
mod tests;
