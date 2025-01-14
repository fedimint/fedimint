use std::collections::BTreeMap;
use std::iter::once;

use anyhow::{Context, ensure};
use async_trait::async_trait;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use fedimint_core::bitcoin::hashes::sha256;
use fedimint_core::config::{DkgMessage, P2PMessage};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::PeerHandle;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::net::peers::{DynP2PConnections, Recipient};
use fedimint_core::{NumPeers, PeerId};
use group::Curve;
use group::ff::Field;
use rand::rngs::OsRng;

// Implementation of the classic Pedersen DKG.

struct Dkg {
    num_peers: NumPeers,
    identity: PeerId,
    polynomial: Vec<Scalar>,
    hash_commitments: BTreeMap<PeerId, sha256::Hash>,
    commitments: BTreeMap<PeerId, Vec<(G1Projective, G2Projective)>>,
    sk_shares: BTreeMap<PeerId, Scalar>,
}

impl Dkg {
    fn new(num_peers: NumPeers, identity: PeerId) -> Self {
        let polynomial = (0..num_peers.threshold())
            .map(|_| Scalar::random(&mut OsRng))
            .collect::<Vec<Scalar>>();

        let commitment = polynomial
            .iter()
            .map(|f| (g1(f), g2(f)))
            .collect::<Vec<(G1Projective, G2Projective)>>();

        Dkg {
            num_peers,
            identity,
            polynomial: polynomial.clone(),
            hash_commitments: once((identity, commitment.consensus_hash_sha256())).collect(),
            commitments: once((identity, commitment)).collect(),
            sk_shares: BTreeMap::new(),
        }
    }

    fn commitment(&self) -> Vec<(G1Projective, G2Projective)> {
        self.polynomial.iter().map(|f| (g1(f), g2(f))).collect()
    }

    fn initial_message(&self) -> DkgMessage {
        DkgMessage::Hash(self.commitment().consensus_hash_sha256())
    }

    /// Runs a single step of the DKG algorithm
    fn step(&mut self, peer: PeerId, msg: DkgMessage) -> anyhow::Result<DkgStep> {
        match msg {
            DkgMessage::Hash(hash) => {
                ensure!(
                    self.hash_commitments.insert(peer, hash).is_none(),
                    "DKG: peer {peer} sent us two hash commitments."
                );

                if self.hash_commitments.len() == self.num_peers.total() {
                    return Ok(DkgStep::Broadcast(DkgMessage::Commitment(
                        self.commitment(),
                    )));
                }
            }
            DkgMessage::Commitment(polynomial) => {
                ensure!(
                    *self
                        .hash_commitments
                        .get(&peer)
                        .context("DKG: hash commitment not found for peer {peer}")?
                        == polynomial.consensus_hash_sha256(),
                    "DKG: polynomial commitment from peer {peer} is of wrong degree."
                );

                ensure!(
                    self.num_peers.threshold() == polynomial.len(),
                    "DKG: polynomial commitment from peer {peer} is of wrong degree."
                );

                ensure!(
                    self.commitments.insert(peer, polynomial).is_none(),
                    "DKG: peer {peer} sent us two commitments."
                );

                // Once everyone has send their commitments, send out the key shares...

                if self.commitments.len() == self.num_peers.total() {
                    let mut messages = vec![];

                    for peer in self.num_peers.peer_ids() {
                        let s = eval_poly_scalar(&self.polynomial, &scalar(&peer));

                        if peer == self.identity {
                            self.sk_shares.insert(self.identity, s);
                        } else {
                            messages.push((peer, DkgMessage::Share(s)));
                        }
                    }

                    return Ok(DkgStep::Messages(messages));
                }
            }
            DkgMessage::Share(s) => {
                let polynomial = self
                    .commitments
                    .get(&peer)
                    .context("DKG: polynomial commitment not found for peer {peer}.")?;

                let checksum: (G1Projective, G2Projective) = polynomial
                    .iter()
                    .zip((0..).map(|k| scalar(&self.identity).pow(&[k, 0, 0, 0])))
                    .map(|(c, x)| (c.0 * x, c.1 * x))
                    .reduce(|(a1, a2), (b1, b2)| (a1 + b1, a2 + b2))
                    .expect("DKG: polynomial commitment from peer {peer} is empty.");

                ensure!(
                    (g1(&s), g2(&s)) == checksum,
                    "DKG: share from {peer} is invalid."
                );

                ensure!(
                    self.sk_shares.insert(peer, s).is_none(),
                    "Peer {peer} sent us two sk shares."
                );

                if self.sk_shares.len() == self.num_peers.total() {
                    let sks = self.sk_shares.values().sum();

                    let pks = (0..self.num_peers.threshold())
                        .map(|i| {
                            self.commitments
                                .values()
                                .map(|coefficients| coefficients[i])
                                .reduce(|(a1, a2), (b1, b2)| (a1 + b1, a2 + b2))
                                .expect("DKG: polynomial commitments are empty.")
                        })
                        .collect();

                    return Ok(DkgStep::Result((pks, sks)));
                }
            }
        }

        Ok(DkgStep::Messages(vec![]))
    }
}

fn g1(scalar: &Scalar) -> G1Projective {
    G1Projective::generator() * scalar
}

fn g2(scalar: &Scalar) -> G2Projective {
    G2Projective::generator() * scalar
}

// Offset by 1, since evaluating a poly at 0 reveals the secret
fn scalar(peer: &PeerId) -> Scalar {
    Scalar::from(peer.to_usize() as u64 + 1)
}

/// Runs the DKG algorithms with our peers. We do not handle any unexpected
/// messages and all peers are expected to be cooperative.
pub async fn run_dkg(
    num_peers: NumPeers,
    identity: PeerId,
    connections: &DynP2PConnections<P2PMessage>,
) -> anyhow::Result<(Vec<(G1Projective, G2Projective)>, Scalar)> {
    let mut dkg = Dkg::new(num_peers, identity);

    connections
        .send(Recipient::Everyone, P2PMessage::Dkg(dkg.initial_message()))
        .await;

    loop {
        for peer in num_peers.peer_ids().filter(|p| *p != identity) {
            let message = connections
                .receive_from_peer(peer)
                .await
                .context("Unexpected shutdown of p2p connections during dkg")?;

            let message = match message {
                P2PMessage::Dkg(message) => message,
                _ => anyhow::bail!("Received unexpected message: {message:?}"),
            };

            match dkg.step(peer, message)? {
                DkgStep::Broadcast(message) => {
                    connections
                        .send(Recipient::Everyone, P2PMessage::Dkg(message))
                        .await;
                }
                DkgStep::Messages(messages) => {
                    for (peer, message) in messages {
                        connections
                            .send(Recipient::Peer(peer), P2PMessage::Dkg(message))
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

fn eval_poly_scalar(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients
        .iter()
        .copied()
        .rev()
        .reduce(|acc, coefficient| acc * x + coefficient)
        .expect("We have at least one coefficient")
}

enum DkgStep {
    Broadcast(DkgMessage),
    Messages(Vec<(PeerId, DkgMessage)>),
    Result((Vec<(G1Projective, G2Projective)>, Scalar)),
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
        run_dkg(self.num_peers, self.identity, self.connections)
            .await
            .map(|(poly, sk)| (poly.into_iter().map(|c| c.0).collect(), sk))
    }

    async fn run_dkg_g2(&self) -> anyhow::Result<(Vec<G2Projective>, Scalar)> {
        run_dkg(self.num_peers, self.identity, self.connections)
            .await
            .map(|(poly, sk)| (poly.into_iter().map(|c| c.1).collect(), sk))
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
    use std::collections::{BTreeMap, VecDeque};

    use bls12_381::{G1Projective, G2Projective};
    use fedimint_core::{NumPeersExt, PeerId};
    use group::Curve;

    use crate::config::distributedgen::{Dkg, DkgStep, eval_poly_g1, eval_poly_g2, g1, g2};

    #[test_log::test]
    fn test_dkg() {
        let peers = (0..7_u16).map(PeerId::from).collect::<Vec<PeerId>>();

        let mut dkgs = peers
            .iter()
            .map(|peer| (*peer, Dkg::new(peers.to_num_peers(), *peer)))
            .collect::<BTreeMap<PeerId, Dkg>>();

        let mut steps = dkgs
            .iter()
            .map(|(peer, dkg)| (*peer, DkgStep::Broadcast(dkg.initial_message())))
            .collect::<VecDeque<(PeerId, DkgStep)>>();

        let mut keys = BTreeMap::new();

        while keys.len() < peers.len() {
            match steps.pop_front().unwrap() {
                (send_peer, DkgStep::Broadcast(message)) => {
                    for receive_peer in peers.iter().filter(|p| **p != send_peer) {
                        let step = dkgs
                            .get_mut(receive_peer)
                            .unwrap()
                            .step(send_peer, message.clone());

                        steps.push_back((*receive_peer, step.unwrap()));
                    }
                }
                (send_peer, DkgStep::Messages(messages)) => {
                    for (receive_peer, messages) in messages {
                        let step = dkgs
                            .get_mut(&receive_peer)
                            .unwrap()
                            .step(send_peer, messages);

                        steps.push_back((receive_peer, step.unwrap()));
                    }
                }
                (send_peer, DkgStep::Result(step_keys)) => {
                    keys.insert(send_peer, step_keys);
                }
            }
        }

        assert!(steps.is_empty());

        for (peer, (poly, sks)) in keys {
            let poly_g1: Vec<G1Projective> = poly.clone().into_iter().map(|c| c.0).collect();
            let poly_g2: Vec<G2Projective> = poly.clone().into_iter().map(|c| c.1).collect();

            assert_eq!(poly_g1.len(), 5);
            assert_eq!(eval_poly_g1(&poly_g1, &peer), g1(&sks).to_affine());

            assert_eq!(poly_g2.len(), 5);
            assert_eq!(eval_poly_g2(&poly_g2, &peer), g2(&sks).to_affine());
        }
    }
}
