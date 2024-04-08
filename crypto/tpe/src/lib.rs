use std::collections::BTreeMap;
use std::ops::Mul;

use bitcoin_hashes::{sha256, Hash};
use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
pub use bls12_381::{G1Affine, G2Affine};
use fedimint_core::bls12_381_serde;
use fedimint_core::encoding::{Decodable, Encodable};
use ff::Field;
use group::{Curve, Group};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct SecretKeyShare(#[serde(with = "bls12_381_serde::scalar")] pub Scalar);

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

pub fn verify_ciphertext(ct: &CipherText, commitment: &sha256::Hash) -> bool {
    let message = hash_to_message(&ct.encrypted_preimage, &ct.pk.0, commitment);

    pairing(&G1Affine::generator(), &ct.signature.0) == pairing(&ct.pk.0, &message)
}

pub fn decrypt_preimage(ct: &CipherText, agg_dk: &AggregateDecryptionKey) -> [u8; 32] {
    xor_with_hash(ct.encrypted_preimage, agg_dk)
}

pub fn derive_agg_decryption_key(
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

pub fn encrypt_preimage(
    agg_pk: &AggregatePublicKey,
    encryption_seed: &[u8; 32],
    preimage: &[u8; 32],
    commitment: &sha256::Hash,
) -> CipherText {
    let agg_dk = derive_agg_decryption_key(agg_pk, encryption_seed);
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

pub fn verify_agg_decryption_key(
    agg_pk: &AggregatePublicKey,
    agg_dk: &AggregateDecryptionKey,
    ct: &CipherText,
    commitment: &sha256::Hash,
) -> bool {
    let message = hash_to_message(&ct.encrypted_preimage, &ct.pk.0, commitment);

    pairing(&agg_dk.0, &message) == pairing(&agg_pk.0, &ct.signature.0)
}

pub fn create_decryption_key_share(sks: &SecretKeyShare, ct: &CipherText) -> DecryptionKeyShare {
    DecryptionKeyShare(ct.pk.0.mul(sks.0).to_affine())
}

pub fn verify_decryption_key_share(
    pks: &PublicKeyShare,
    dks: &DecryptionKeyShare,
    ct: &CipherText,
    commitment: &sha256::Hash,
) -> bool {
    let message = hash_to_message(&ct.encrypted_preimage, &ct.pk.0, commitment);

    pairing(&dks.0, &message) == pairing(&pks.0, &ct.signature.0)
}

fn xor_with_hash(mut bytes: [u8; 32], agg_dk: &AggregateDecryptionKey) -> [u8; 32] {
    let hash = agg_dk.consensus_hash::<sha256::Hash>();

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
    let message = (
        "FEDIMINT_TPE_BLS12_381_MESSAGE",
        *encrypted_point,
        *ephemeral_pk,
        *commitment,
    );

    let seed = message.consensus_hash::<sha256::Hash>().into_inner();

    G2Projective::random(&mut ChaChaRng::from_seed(seed)).to_affine()
}

pub fn aggregate_decryption_shares(
    shares: &BTreeMap<u64, DecryptionKeyShare>,
) -> AggregateDecryptionKey {
    AggregateDecryptionKey(
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

macro_rules! impl_hash_with_serialized_compressed {
    ($type:ty) => {
        #[allow(clippy::derived_hash_with_manual_eq)]
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
mod tests {
    use std::collections::BTreeMap;

    use bitcoin_hashes::{sha256, Hash};
    use bls12_381::{G1Projective, Scalar};
    use ff::Field;
    use group::Curve;
    use rand::rngs::OsRng;

    use crate::{
        aggregate_decryption_shares, create_decryption_key_share, decrypt_preimage,
        derive_agg_decryption_key, encrypt_preimage, verify_agg_decryption_key,
        verify_decryption_key_share, AggregatePublicKey, DecryptionKeyShare, PublicKeyShare,
        SecretKeyShare,
    };

    fn dealer_keygen(
        threshold: usize,
        keys: usize,
    ) -> (AggregatePublicKey, Vec<PublicKeyShare>, Vec<SecretKeyShare>) {
        let poly: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(&mut OsRng)).collect();

        let apk = (G1Projective::generator() * eval_polynomial(&poly, &Scalar::zero())).to_affine();

        let sks: Vec<SecretKeyShare> = (0..keys)
            .map(|idx| SecretKeyShare(eval_polynomial(&poly, &Scalar::from(idx as u64 + 1))))
            .collect();

        let pks = sks
            .iter()
            .map(|sk| PublicKeyShare((G1Projective::generator() * sk.0).to_affine()))
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
        let (agg_pk, pks, sks) = dealer_keygen(3, 4);

        let encryption_seed = [7_u8; 32];
        let preimage = [42_u8; 32];
        let commitment = sha256::Hash::hash(&[0_u8; 32]);
        let ciphertext = encrypt_preimage(&agg_pk, &encryption_seed, &preimage, &commitment);

        let shares: Vec<DecryptionKeyShare> = sks
            .iter()
            .map(|sk| create_decryption_key_share(sk, &ciphertext))
            .collect();

        for (pk, share) in pks.iter().zip(shares.iter()) {
            assert!(verify_decryption_key_share(
                pk,
                share,
                &ciphertext,
                &commitment
            ));
        }

        let selected_shares: BTreeMap<u64, DecryptionKeyShare> = (1_u64..4).zip(shares).collect();

        assert_eq!(selected_shares.len(), 3);

        let agg_dk = aggregate_decryption_shares(&selected_shares);

        assert_eq!(agg_dk, derive_agg_decryption_key(&agg_pk, &encryption_seed));

        assert!(verify_agg_decryption_key(
            &agg_pk,
            &agg_dk,
            &ciphertext,
            &commitment
        ));

        assert_eq!(preimage, decrypt_preimage(&ciphertext, &agg_dk));
    }
}
