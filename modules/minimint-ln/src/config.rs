use async_trait::async_trait;
use minimint_api::config::GenerateConfig;
use minimint_api::rand::Rand07Compat;
use minimint_api::PeerId;
use secp256k1::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

use minimint_api::net::peers::AnyPeerConnections;
use threshold_crypto::ff::Field;
use threshold_crypto::group::{CurveAffine, CurveProjective};
use threshold_crypto::poly::{BivarCommitment, BivarPoly, Poly};
use threshold_crypto::{Fr, G1Affine, PublicKeySet, SecretKeyShare, G1};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleConfig {
    pub threshold_pub_keys: PublicKeySet,
    // TODO: propose serde(with = "…") based protection upstream instead
    pub threshold_sec_key: threshold_crypto::serde_impl::SerdeSecret<SecretKeyShare>,
    pub threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleClientConfig {
    pub threshold_pub_key: threshold_crypto::PublicKey,
}

#[async_trait(?Send)]
impl GenerateConfig for LightningModuleConfig {
    type Params = ();
    type ClientConfig = LightningModuleClientConfig;
    type ConfigMessage = ThresholdKeyGen;
    type ConfigError = ();

    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        _params: &Self::Params,
        rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let threshold = peers.len() - max_evil - 1;
        let sks = threshold_crypto::SecretKeySet::random(threshold, &mut Rand07Compat(rng));
        let pks = sks.public_keys();

        let server_cfg = peers
            .iter()
            .map(|&peer| {
                let sk = sks.secret_key_share(peer.to_usize());

                (
                    peer,
                    LightningModuleConfig {
                        threshold_pub_keys: pks.clone(),
                        threshold_sec_key: threshold_crypto::serde_impl::SerdeSecret(sk),
                        threshold,
                    },
                )
            })
            .collect();

        let client_cfg = LightningModuleClientConfig {
            threshold_pub_key: pks.public_key(),
        };

        (server_cfg, client_cfg)
    }

    async fn distributed_gen(
        connections: &mut AnyPeerConnections<Self::ConfigMessage>,
        our_id: &PeerId,
        peers: &[PeerId],
        max_evil: usize,
        _params: &mut Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, Self::ClientConfig), Self::ConfigError> {
        let threshold = peers.len() - max_evil - 1;
        let (mut sk, pk) =
            Self::distributed_threshold_gen(connections, our_id, peers, threshold, &mut rng).await;

        let server_cfg = LightningModuleConfig {
            threshold_pub_keys: pk.clone(),
            threshold_sec_key: threshold_crypto::serde_impl::SerdeSecret(SecretKeyShare::from_mut(
                &mut sk,
            )),
            threshold,
        };

        let client_cfg = LightningModuleClientConfig {
            threshold_pub_key: pk.public_key(),
        };

        Ok((server_cfg, client_cfg))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum ThresholdKeyGen {
    Commit(Poly, BivarCommitment),
    Verify(BivarCommitment, #[serde(with = "serde_g1")] G1),
}

impl LightningModuleConfig {
    pub async fn distributed_threshold_gen<'a>(
        connections: &mut AnyPeerConnections<ThresholdKeyGen>,
        our_id: &'a PeerId,
        peers: &'a [PeerId],
        threshold: usize,
        rng: &'a mut (impl RngCore + CryptoRng),
    ) -> (Fr, PublicKeySet) {
        let mut sk: Fr = Fr::zero();
        let mut pk = Poly::zero().commitment();
        let mut commits = BTreeMap::<PeerId, (Poly, BivarCommitment)>::new();
        let mut verifies = BTreeMap::<BivarCommitment, HashSet<PeerId>>::new();

        // create our secrets and add them to our keys
        let our_poly = BivarPoly::random(threshold, &mut Rand07Compat(rng));
        let our_commit = BivarPoly::commitment(&our_poly);
        sk.add_assign(&our_poly.row(our_id.as_row()).evaluate(Fr::zero()));
        pk += our_commit.row(0_usize);

        for peer in peers {
            let msg = ThresholdKeyGen::Commit(our_poly.row(peer.as_row()), our_commit.clone());
            connections.send(&[*peer], msg).await;
        }

        // run until all other peers have verified every commit
        let num_others = peers.len() - 1;

        while verifies.values().map(|v| v.len()).sum::<usize>() < (peers.len() * num_others) {
            match connections.receive().await {
                (sender, ThresholdKeyGen::Commit(poly, commit)) => {
                    for peer in peers {
                        let val = poly.evaluate(peer.as_row());
                        let val_g1 = G1Affine::one().mul(val).into_affine().into_projective();
                        connections
                            .send(&[*peer], ThresholdKeyGen::Verify(commit.clone(), val_g1))
                            .await;
                    }

                    // verify commitment and that each peer only sends 1
                    assert_eq!(poly.commitment(), commit.row(our_id.as_row()));
                    assert!(commits.insert(sender, (poly, commit.clone())).is_none());
                    let verifiers = verifies.entry(commit).or_insert_with(HashSet::default);
                    verifiers.insert(*our_id);
                }
                (sender, ThresholdKeyGen::Verify(commit, val_g1)) => {
                    // verify and add commitment
                    assert_eq!(commit.evaluate(sender.as_row(), our_id.as_row()), val_g1);
                    let verifiers = verifies.entry(commit).or_insert_with(HashSet::default);
                    verifiers.insert(sender);
                }
            }
        }

        assert_eq!(commits.len(), num_others);
        commits.values().for_each(|(poly, commit)| {
            // add to our secret key and public key, asserting there were enough verifications
            assert_eq!(verifies.get(commit).unwrap().len(), num_others);
            sk.add_assign(&poly.evaluate(Fr::zero()));
            pk += commit.row(0_usize);
        });

        (sk, PublicKeySet::from(pk))
    }
}

mod serde_g1 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use threshold_crypto::group::{CurveAffine, CurveProjective, EncodedPoint};
    use threshold_crypto::pairing::bls12_381::G1Compressed;
    use threshold_crypto::G1;

    pub fn serialize<S>(key: &G1, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.into_affine().into_compressed();
        serializer.serialize_bytes(bytes.as_ref())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<G1, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 48 {
            return Err(D::Error::invalid_length(bytes.len(), &"48 bytes"));
        }
        let mut g1 = G1Compressed::empty();
        g1.as_mut().copy_from_slice(&bytes);
        Ok(g1.into_affine().unwrap().into_projective())
    }
}

trait PeerRow {
    fn as_row(&self) -> usize;
}

impl PeerRow for PeerId {
    fn as_row(&self) -> usize {
        (u16::from(*self) as usize) + 1
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ThresholdKeyGen;
    use minimint_api::rand::Rand07Compat;
    use secp256k1::rand::prelude::ThreadRng;
    use std::collections::BTreeMap;
    use threshold_crypto::ff::Field;
    use threshold_crypto::group::{CurveAffine, CurveProjective};
    use threshold_crypto::poly::{BivarCommitment, BivarPoly, Poly};
    use threshold_crypto::{Fr, G1Affine, PublicKeySet, SecretKeyShare, G1};

    fn rng() -> Rand07Compat<ThreadRng> {
        Rand07Compat(secp256k1::rand::thread_rng())
    }

    #[test]
    fn test_g1_serde() {
        let commit = BivarPoly::random(1, &mut rng()).commitment();
        let g1 = ThresholdKeyGen::Verify(commit, G1::random(&mut rng()));
        let g1_deser = serde_json::from_str(&serde_json::to_string(&g1).unwrap()).unwrap();
        assert_eq!(g1, g1_deser);
    }

    #[test]
    fn test_threshold_sigs() {
        let peers = 4;
        let max_evil = 1;
        let threshold = peers - max_evil;

        let polys: Vec<BivarPoly> = (0..peers)
            .map(|_| BivarPoly::random(threshold - 1, &mut rng()))
            .collect();
        let commits: Vec<BivarCommitment> = polys.iter().map(BivarPoly::commitment).collect();

        let mut sum_commit = Poly::zero().commitment();

        let mut sks: Vec<Fr> = vec![Fr::zero(); peers];
        for (our_poly, commit) in polys.iter().zip(commits) {
            for (i, sk) in sks.iter_mut().enumerate() {
                let poly = our_poly.row(i + 1);
                assert_eq!(poly.commitment(), commit.row(i + 1));

                for j in 0..polys.len() {
                    let val = poly.evaluate(j + 1);
                    let val_g1 = G1Affine::one().mul(val);
                    assert_eq!(commit.evaluate(i + 1, j + 1), val_g1);
                }

                sk.add_assign(&poly.evaluate(Fr::zero()));
            }
            sum_commit += commit.row(0_usize);
        }

        let threshold_pub_key = PublicKeySet::from(sum_commit);
        let sk1 = SecretKeyShare::from_mut(&mut sks[0].clone());
        assert_eq!(
            threshold_pub_key.public_key_share(0_usize),
            sk1.public_key_share()
        );

        let msg = b"Totally real news";
        let ciphertext = threshold_pub_key.public_key().encrypt(&msg[..]);

        let shares: BTreeMap<_, _> = sks
            .iter_mut()
            .enumerate()
            .take(threshold)
            .map(|(i, sk)| {
                let dec_share = SecretKeyShare::from_mut(sk)
                    .decrypt_share(&ciphertext)
                    .expect("ciphertext is invalid");
                (i, dec_share)
            })
            .collect();

        let decrypted = threshold_pub_key
            .decrypt(&shares, &ciphertext)
            .expect("decryption shares match");
        assert_eq!(msg[..], decrypted[..]);
    }
}
