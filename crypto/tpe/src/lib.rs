use std::collections::BTreeMap;
use std::io::Write;
use std::ops::Mul;

use bitcoin_hashes::{Hash, sha256};
pub use bls12_381::{G1Affine, G2Affine};
use bls12_381::{G1Projective, G2Projective, Scalar, pairing};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{bls12_381_serde, hex};
use group::ff::Field;
use group::{Curve, Group};
use rand_chacha::ChaChaRng;
use rand_chacha::rand_core::SeedableRng;
use serde::{Deserialize, Serialize};

const FINGERPRINT_TAG: &[u8] = b"TPE_SKS_FP";

#[derive(Copy, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct SecretKeyShare(#[serde(with = "bls12_381_serde::scalar")] pub Scalar);

impl std::fmt::Debug for SecretKeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if fedimint_core::fmt_utils::show_secrets() || f.alternate() {
            f.debug_tuple("SecretKeyShare")
                .field(&hex::encode(self.0.to_bytes()))
                .finish()
        } else {
            // Show fingerprint instead of actual secret
            // Hash directly into hasher to avoid allocation
            use bitcoin_hashes::HashEngine;
            let mut engine = sha256::HashEngine::default();
            engine.input(FINGERPRINT_TAG);
            engine.input(&self.0.to_bytes());
            let hash = sha256::Hash::from_engine(engine);
            write!(f, "SecretKeyShare#<{}>", hex::encode(&hash[..8]))
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct PublicKeyShare(#[serde(with = "bls12_381_serde::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct AggregatePublicKey(#[serde(with = "bls12_381_serde::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct DecryptionKeyShare(#[serde(with = "bls12_381_serde::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct AggregateDecryptionKey(#[serde(with = "bls12_381_serde::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct EphemeralPublicKey(#[serde(with = "bls12_381_serde::g1")] pub G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct EphemeralSignature(#[serde(with = "bls12_381_serde::g2")] pub G2Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct CipherText {
    #[serde(with = "serde_big_array::BigArray")]
    pub encrypted_preimage: [u8; 32],
    pub pk: EphemeralPublicKey,
    pub signature: EphemeralSignature,
}

pub fn derive_pk_share(sk: &SecretKeyShare) -> PublicKeyShare {
    PublicKeyShare(G1Projective::generator().mul(sk.0).to_affine())
}

pub fn encrypt_preimage(
    agg_pk: &AggregatePublicKey,
    encryption_seed: &[u8; 32],
    preimage: &[u8; 32],
    commitment: &sha256::Hash,
) -> CipherText {
    let agg_dk = derive_agg_dk(agg_pk, encryption_seed);
    let encrypted_preimage = xor_with_hash(*preimage, &agg_dk);

    let ephemeral_sk = derive_ephemeral_sk(encryption_seed);
    let ephemeral_pk = G1Projective::generator().mul(ephemeral_sk).to_affine();
    let ephemeral_signature = hash_to_message(&encrypted_preimage, &ephemeral_pk, commitment)
        .mul(ephemeral_sk)
        .to_affine();

    CipherText {
        encrypted_preimage,
        pk: EphemeralPublicKey(ephemeral_pk),
        signature: EphemeralSignature(ephemeral_signature),
    }
}

pub fn derive_agg_dk(
    agg_pk: &AggregatePublicKey,
    encryption_seed: &[u8; 32],
) -> AggregateDecryptionKey {
    AggregateDecryptionKey(
        agg_pk
            .0
            .mul(derive_ephemeral_sk(encryption_seed))
            .to_affine(),
    )
}

fn derive_ephemeral_sk(encryption_seed: &[u8; 32]) -> Scalar {
    Scalar::random(&mut ChaChaRng::from_seed(*encryption_seed))
}

fn xor_with_hash(mut bytes: [u8; 32], agg_dk: &AggregateDecryptionKey) -> [u8; 32] {
    let hash = sha256::Hash::hash(&agg_dk.0.to_compressed());

    for i in 0..32 {
        bytes[i] ^= hash[i];
    }

    bytes
}

fn hash_to_message(
    encrypted_point: &[u8; 32],
    ephemeral_pk: &G1Affine,
    commitment: &sha256::Hash,
) -> G2Affine {
    let mut engine = sha256::HashEngine::default();

    engine
        .write_all("FEDIMINT_TPE_BLS12_381_MESSAGE".as_bytes())
        .expect("Writing to a hash engine cannot fail");

    engine
        .write_all(encrypted_point)
        .expect("Writing to a hash engine cannot fail");

    engine
        .write_all(&ephemeral_pk.to_compressed())
        .expect("Writing to a hash engine cannot fail");

    engine
        .write_all(commitment.as_byte_array())
        .expect("Writing to a hash engine cannot fail");

    let seed = sha256::Hash::from_engine(engine).to_byte_array();

    G2Projective::random(&mut ChaChaRng::from_seed(seed)).to_affine()
}

/// Verifying a ciphertext guarantees that it has not been malleated.
pub fn verify_ciphertext(ct: &CipherText, commitment: &sha256::Hash) -> bool {
    let message = hash_to_message(&ct.encrypted_preimage, &ct.pk.0, commitment);

    pairing(&G1Affine::generator(), &ct.signature.0) == pairing(&ct.pk.0, &message)
}

pub fn decrypt_preimage(ct: &CipherText, agg_dk: &AggregateDecryptionKey) -> [u8; 32] {
    xor_with_hash(ct.encrypted_preimage, agg_dk)
}

/// The function asserts that the ciphertext is valid.
pub fn verify_agg_dk(
    agg_pk: &AggregatePublicKey,
    agg_dk: &AggregateDecryptionKey,
    ct: &CipherText,
    commitment: &sha256::Hash,
) -> bool {
    let message = hash_to_message(&ct.encrypted_preimage, &ct.pk.0, commitment);

    assert_eq!(
        pairing(&G1Affine::generator(), &ct.signature.0),
        pairing(&ct.pk.0, &message)
    );

    // Since the ciphertext is valid its signature is the ecdh point of the message
    // and the ephemeral public key. Hence, the following equation holds if and only
    // if the aggregate decryption key is the ecdh point of the ephemeral public key
    // and the aggregate public key.

    pairing(&agg_dk.0, &message) == pairing(&agg_pk.0, &ct.signature.0)
}

pub fn create_dk_share(sks: &SecretKeyShare, ct: &CipherText) -> DecryptionKeyShare {
    DecryptionKeyShare(ct.pk.0.mul(sks.0).to_affine())
}

/// The function asserts that the ciphertext is valid.
pub fn verify_dk_share(
    pks: &PublicKeyShare,
    dks: &DecryptionKeyShare,
    ct: &CipherText,
    commitment: &sha256::Hash,
) -> bool {
    let message = hash_to_message(&ct.encrypted_preimage, &ct.pk.0, commitment);

    assert_eq!(
        pairing(&G1Affine::generator(), &ct.signature.0),
        pairing(&ct.pk.0, &message)
    );

    // Since the ciphertext is valid its signature is the ecdh point of the message
    // and the ephemeral public key. Hence, the following equation holds if and only
    // if the decryption key share is the ecdh point of the ephemeral public key and
    // the public key share.

    pairing(&dks.0, &message) == pairing(&pks.0, &ct.signature.0)
}

pub fn aggregate_dk_shares(shares: &BTreeMap<u64, DecryptionKeyShare>) -> AggregateDecryptionKey {
    AggregateDecryptionKey(
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

macro_rules! impl_hash_with_serialized_compressed {
    ($type:ty) => {
        impl std::hash::Hash for $type {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                state.write(&self.0.to_compressed());
            }
        }
    };
}

impl_hash_with_serialized_compressed!(AggregatePublicKey);
impl_hash_with_serialized_compressed!(DecryptionKeyShare);
impl_hash_with_serialized_compressed!(AggregateDecryptionKey);
impl_hash_with_serialized_compressed!(EphemeralPublicKey);
impl_hash_with_serialized_compressed!(EphemeralSignature);
impl_hash_with_serialized_compressed!(PublicKeyShare);

#[cfg(test)]
mod tests;
