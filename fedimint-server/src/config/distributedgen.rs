use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Write;

use anyhow::{ensure, Context};
use async_trait::async_trait;
use bitcoin::hashes::sha256::{Hash as Sha256, HashEngine};
use bitcoin::hashes::Hash as BitcoinHash;
use bls12_381::Scalar;
use fedimint_core::config::{DkgGroup, DkgMessage, ISupportedDkgMessage, P2PMessage};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::PeerHandle;
use fedimint_core::net::peers::{DynP2PConnections, Recipient};
use fedimint_core::{NumPeers, PeerId};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use threshold_crypto::ff::Field;
use threshold_crypto::group::Curve;
use threshold_crypto::{G1Affine, G1Projective, G2Affine, G2Projective};

struct Dkg<G> {
    num_peers: NumPeers,
    identity: PeerId,
    generator: G,
    f1_poly: Vec<Scalar>,
    f2_poly: Vec<Scalar>,
    hashed_commits: BTreeMap<PeerId, Sha256>,
    commitments: BTreeMap<PeerId, Vec<G>>,
    sk_shares: BTreeMap<PeerId, Scalar>,
    pk_shares: BTreeMap<PeerId, Vec<G>>,
}

/// Implementation of "Secure Distributed Key Generation for Discrete-Log Based
/// Cryptosystems" by Rosario Gennaro and Stanislaw Jarecki and Hugo Krawczyk
/// and Tal Rabin
///
/// Prevents any manipulation of the secret key, but fails with any
/// non-cooperative peers
impl<G: DkgGroup> Dkg<G> {
    /// Creates the DKG and the first step of the algorithm
    pub fn new(num_peers: NumPeers, identity: PeerId, generator: G) -> (Self, DkgMessage<G>) {
        let f1_poly = random_coefficients(num_peers.threshold() - 1);
        let f2_poly = random_coefficients(num_peers.threshold() - 1);

        let mut dkg = Dkg {
            num_peers,
            identity,
            generator,
            f1_poly,
            f2_poly,
            hashed_commits: BTreeMap::new(),
            commitments: BTreeMap::new(),
            sk_shares: BTreeMap::new(),
            pk_shares: BTreeMap::new(),
        };

        // broadcast our commitment to the polynomials
        let commit: Vec<G> = dkg
            .f1_poly
            .iter()
            .map(|c| dkg.generator * *c)
            .zip(dkg.f2_poly.iter().map(|c| gen_h::<G>() * *c))
            .map(|(g, h)| g + h)
            .collect();

        let hashed = Dkg::hash(&commit);

        dkg.commitments.insert(identity, commit);
        dkg.hashed_commits.insert(identity, hashed);

        (dkg, DkgMessage::HashedCommit(hashed))
    }

    /// Runs a single step of the DKG algorithm, processing a `msg` from `peer`
    pub fn step(&mut self, peer: PeerId, msg: DkgMessage<G>) -> anyhow::Result<DkgStep<G>> {
        match msg {
            DkgMessage::HashedCommit(hashed) => {
                ensure!(
                    self.hashed_commits.insert(peer, hashed).is_none(),
                    "DKG: peer {peer} sent us two hash commitments."
                );

                if self.hashed_commits.len() == self.num_peers.total() {
                    let commit = self
                        .commitments
                        .get(&self.identity)
                        .expect("DKG hash commitment not found for identity.")
                        .clone();

                    return Ok(DkgStep::Broadcast(DkgMessage::Commit(commit)));
                }
            }
            DkgMessage::Commit(commit) => {
                ensure!(
                    self.num_peers.threshold() == commit.len(),
                    "DKG: polynomial commitment from peer {peer} is of wrong degree."
                );

                let hash_commitment = *self
                    .hashed_commits
                    .get(&peer)
                    .context("DKG: hash commitment not found for peer {peer}")?;

                ensure!(
                    Self::hash(&commit) == hash_commitment,
                    "DKG: polynomial commitment from peer {peer} has invalid hash."
                );

                ensure!(
                    self.commitments.insert(peer, commit).is_none(),
                    "DKG: peer {peer} sent us two commitments."
                );

                // once everyone has made commitments, send out shares
                if self.commitments.len() == self.num_peers.total() {
                    let mut messages = vec![];

                    for peer in self.num_peers.peer_ids() {
                        let s1 = eval_poly_scalar(&self.f1_poly, &scalar(&peer));
                        let s2 = eval_poly_scalar(&self.f2_poly, &scalar(&peer));

                        if peer == self.identity {
                            self.sk_shares.insert(self.identity, s1);
                        } else {
                            messages.push((peer, DkgMessage::Share(s1, s2)));
                        }
                    }

                    return Ok(DkgStep::Messages(messages));
                }
            }
            // Pedersen-VSS verifies the shares match the commitments
            DkgMessage::Share(s1, s2) => {
                let share_product: G = (self.generator * s1) + (gen_h::<G>() * s2);

                let commitment = self
                    .commitments
                    .get(&peer)
                    .context("DKG: polynomial commitment not found for peer {peer}.")?;

                let commit_product: G = commitment
                    .iter()
                    .enumerate()
                    .map(|(idx, commit)| {
                        *commit * scalar(&self.identity).pow(&[idx as u64, 0, 0, 0])
                    })
                    .reduce(|a, b| a + b)
                    .expect("DKG: polynomial commitment from peer {peer} is empty.");

                ensure!(
                    share_product == commit_product,
                    "DKG: share from {peer} is invalid."
                );

                ensure!(
                    self.sk_shares.insert(peer, s1).is_none(),
                    "Peer {peer} sent us two shares."
                );

                if self.sk_shares.len() == self.num_peers.total() {
                    let extract = self
                        .f1_poly
                        .iter()
                        .map(|c| self.generator * *c)
                        .collect::<Vec<G>>();

                    self.pk_shares.insert(self.identity, extract.clone());

                    return Ok(DkgStep::Broadcast(DkgMessage::Extract(extract)));
                }
            }
            // Feldman-VSS exposes the public key shares
            DkgMessage::Extract(extract) => {
                let share = self
                    .sk_shares
                    .get(&peer)
                    .context("DKG share not found for peer {peer}.")?;

                let extract_product: G = extract
                    .iter()
                    .enumerate()
                    .map(|(idx, commit)| {
                        *commit * scalar(&self.identity).pow(&[idx as u64, 0, 0, 0])
                    })
                    .reduce(|a, b| a + b)
                    .expect("sums");

                ensure!(
                    self.generator * *share == extract_product,
                    "DKG: extract from {peer} is invalid."
                );

                ensure!(
                    self.num_peers.threshold() == extract.len(),
                    "wrong degree from {peer}."
                );

                ensure!(
                    self.pk_shares.insert(peer, extract).is_none(),
                    "DKG: peer {peer} sent us two extracts."
                );

                if self.pk_shares.len() == self.num_peers.total() {
                    let sks = self.sk_shares.values().sum();

                    let pks: Vec<G> = (0..self.num_peers.threshold())
                        .map(|i| {
                            self.pk_shares
                                .values()
                                .map(|shares| shares[i])
                                .reduce(|a, b| a + b)
                                .expect("DKG: pk shares are empty.")
                        })
                        .collect();

                    return Ok(DkgStep::Result((pks, sks)));
                }
            }
        }

        Ok(DkgStep::Messages(vec![]))
    }

    fn hash(poly: &[G]) -> Sha256 {
        let mut engine = HashEngine::default();

        for element in poly {
            engine
                .write_all(element.to_bytes().as_ref())
                .expect("Writing to a hash engine cannot fail.");
        }

        Sha256::from_engine(engine)
    }
}

fn gen_h<G: DkgGroup>() -> G {
    G::random(&mut ChaChaRng::from_seed([42; 32]))
}

// `PeerId`s are offset by 1, since evaluating a poly at 0 reveals the secret
fn scalar(peer: &PeerId) -> Scalar {
    Scalar::from(peer.to_usize() as u64 + 1)
}

/// Runs the DKG algorithms with our peers. We do not handle any unexpected
/// messages and all peers are expected to be cooperative.
pub async fn run_dkg<G: DkgGroup>(
    num_peers: NumPeers,
    identity: PeerId,
    generator: G,
    connections: &DynP2PConnections<P2PMessage>,
) -> anyhow::Result<(Vec<G>, Scalar)>
where
    DkgMessage<G>: ISupportedDkgMessage,
{
    let (mut dkg, initial_message) = Dkg::new(num_peers, identity, generator);

    connections
        .send(
            Recipient::Everyone,
            P2PMessage::DistributedGen(initial_message.to_msg()),
        )
        .await;

    loop {
        for peer in num_peers.peer_ids().filter(|p| *p != identity) {
            let message = connections
                .receive_from_peer(peer)
                .await
                .context("Unexpected shutdown of p2p connections")?;

            let message = match message {
                P2PMessage::DistributedGen(message) => message,
                _ => anyhow::bail!("Wrong message received: {message:?}"),
            };

            match dkg.step(peer, ISupportedDkgMessage::from_msg(message)?)? {
                DkgStep::Broadcast(message) => {
                    connections
                        .send(
                            Recipient::Everyone,
                            P2PMessage::DistributedGen(message.to_msg()),
                        )
                        .await;
                }
                DkgStep::Messages(messages) => {
                    for (peer, message) in messages {
                        connections
                            .send(
                                Recipient::Peer(peer),
                                P2PMessage::DistributedGen(message.to_msg()),
                            )
                            .await;
                    }
                }
                DkgStep::Result(result) => {
                    return Ok(result);
                }
            }
        }
    }
}

fn random_coefficients(degree: usize) -> Vec<Scalar> {
    (0..=degree).map(|_| Scalar::random(&mut OsRng)).collect()
}

fn eval_poly_scalar(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients
        .iter()
        .copied()
        .rev()
        .reduce(|acc, coefficient| acc * x + coefficient)
        .expect("We have at least one coefficient")
}

#[derive(Debug, Clone)]
pub enum DkgStep<G: DkgGroup> {
    Broadcast(DkgMessage<G>),
    Messages(Vec<(PeerId, DkgMessage<G>)>),
    Result((Vec<G>, Scalar)),
}

pub fn eval_poly_g1(coefficients: &[G1Projective], peer: &PeerId) -> G1Affine {
    coefficients
        .iter()
        .copied()
        .rev()
        .reduce(|acc, coefficient| acc * scalar(peer) + coefficient)
        .expect("We have at least one coefficient")
        .to_affine()
}

pub fn eval_poly_g2(coefficients: &[G2Projective], peer: &PeerId) -> G2Affine {
    coefficients
        .iter()
        .copied()
        .rev()
        .reduce(|acc, coefficient| acc * scalar(peer) + coefficient)
        .expect("We have at least one coefficient")
        .to_affine()
}

// TODO: this trait is only needed to break the `DkgHandle` impl
// from it's definition that is still in `fedimint-core`
#[async_trait]
pub trait PeerHandleOps {
    async fn run_dkg_g1(&self) -> anyhow::Result<(Vec<G1Projective>, Scalar)>;

    async fn run_dkg_g2(&self) -> anyhow::Result<(Vec<G2Projective>, Scalar)>;

    /// Exchanges a `DkgPeerMsg::Module(Vec<u8>)` with all peers. All peers are
    /// required to be online and submit a response for this to return
    /// properly. The caller's message will be included in the returned
    /// `BTreeMap` under the `PeerId` of this peer. This allows modules to
    /// exchange arbitrary data during distributed key generation.
    async fn exchange_encodable<T: Encodable + Decodable + Send + Sync>(
        &self,
        data: T,
    ) -> anyhow::Result<BTreeMap<PeerId, T>>;
}

#[async_trait]
impl<'a> PeerHandleOps for PeerHandle<'a> {
    async fn run_dkg_g1(&self) -> anyhow::Result<(Vec<G1Projective>, Scalar)> {
        run_dkg(
            self.num_peers,
            self.identity,
            G1Projective::generator(),
            self.connections,
        )
        .await
    }

    async fn run_dkg_g2(&self) -> anyhow::Result<(Vec<G2Projective>, Scalar)> {
        run_dkg(
            self.num_peers,
            self.identity,
            G2Projective::generator(),
            self.connections,
        )
        .await
    }

    async fn exchange_encodable<T: Encodable + Decodable + Send + Sync>(
        &self,
        data: T,
    ) -> anyhow::Result<BTreeMap<PeerId, T>> {
        let mut peer_data: BTreeMap<PeerId, T> = BTreeMap::new();

        self.connections
            .send(
                Recipient::Everyone,
                P2PMessage::Encodable(data.consensus_encode_to_vec()),
            )
            .await;

        peer_data.insert(self.identity, data);

        for peer in self.num_peers.peer_ids().filter(|p| *p != self.identity) {
            let message = self
                .connections
                .receive_from_peer(peer)
                .await
                .context("Unexpected shutdown of p2p connections")?;

            match message {
                P2PMessage::Encodable(bytes) => {
                    peer_data.insert(
                        peer,
                        T::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())?,
                    );
                }
                message => {
                    anyhow::bail!("Invalid message from {peer}: {message:?}");
                }
            }
        }

        Ok(peer_data)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};

    use bls12_381::Scalar;
    use fedimint_core::{NumPeersExt, PeerId};
    use tbs::derive_pk_share;
    use threshold_crypto::poly::Commitment;
    use threshold_crypto::serde_impl::SerdeSecret;
    use threshold_crypto::{G1Projective, G2Projective, PublicKeySet, SecretKeyShare};

    use crate::config::distributedgen::{eval_poly_g2, Dkg, DkgGroup, DkgStep};

    #[test_log::test]
    fn test_dkg() {
        for (peer, (polynomial, mut sks)) in run(G1Projective::generator()) {
            let public_key_set = PublicKeySet::from(Commitment::from(polynomial));
            let secret_key_share = SerdeSecret(SecretKeyShare::from_mut(&mut sks));

            assert_eq!(public_key_set.threshold(), 2);
            assert_eq!(
                public_key_set.public_key_share(peer.to_usize()),
                secret_key_share.public_key_share()
            );
        }

        for (peer, (polynomial, sks)) in run(G2Projective::generator()) {
            assert_eq!(polynomial.len(), 3);
            assert_eq!(
                eval_poly_g2(&polynomial, &peer),
                derive_pk_share(&tbs::SecretKeyShare(sks)).0
            );
        }
    }

    fn run<G: DkgGroup>(group: G) -> HashMap<PeerId, (Vec<G>, Scalar)> {
        let peers = (0..4_u16).map(PeerId::from).collect::<Vec<_>>();

        let mut steps: VecDeque<(PeerId, DkgStep<G>)> = VecDeque::new();
        let mut dkgs: HashMap<PeerId, Dkg<G>> = HashMap::new();
        let mut keys: HashMap<PeerId, (Vec<G>, Scalar)> = HashMap::new();

        for peer in &peers {
            let (dkg, initial_message) = Dkg::new(peers.to_num_peers(), *peer, group);
            dkgs.insert(*peer, dkg);
            steps.push_back((*peer, DkgStep::Broadcast(initial_message)));
        }

        while keys.len() < peers.len() {
            match steps.pop_front() {
                Some((peer, DkgStep::Broadcast(message))) => {
                    for receive_peer in peers.iter().filter(|p| **p != peer) {
                        let receive_dkg = dkgs.get_mut(receive_peer).unwrap();
                        let step = receive_dkg.step(peer, message.clone());
                        steps.push_back((*receive_peer, step.unwrap()));
                    }
                }
                Some((peer, DkgStep::Messages(messages))) => {
                    for (receive_peer, messages) in messages {
                        let receive_dkg = dkgs.get_mut(&receive_peer).unwrap();
                        let step = receive_dkg.step(peer, messages);
                        steps.push_back((receive_peer, step.unwrap()));
                    }
                }
                Some((peer, DkgStep::Result(step_keys))) => {
                    keys.insert(peer, step_keys);
                }
                _ => {}
            }
        }

        assert!(steps.is_empty());

        keys
    }
}
