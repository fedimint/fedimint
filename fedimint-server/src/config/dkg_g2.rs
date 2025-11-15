use std::collections::BTreeMap;
use std::iter::once;

use anyhow::{Context, bail, ensure};
use bls12_381::{G2Projective, Scalar};
use fedimint_core::bitcoin::hashes::sha256;
use fedimint_core::config::{DkgMessageG2, P2PMessage};
use fedimint_core::encoding::Encodable as _;
use fedimint_core::net::peers::{DynP2PConnections, Recipient};
use fedimint_core::{NumPeers, PeerId};
use fedimint_server_core::config::{g2, scalar};
use group::ff::Field;
use rand::rngs::OsRng;
use tracing::trace;

// Implementation of the classic Pedersen DKG for G2.

struct DkgG2 {
    num_peers: NumPeers,
    identity: PeerId,
    polynomial: Vec<Scalar>,
    hash_commitments: BTreeMap<PeerId, sha256::Hash>,
    commitments: BTreeMap<PeerId, Vec<G2Projective>>,
    sk_shares: BTreeMap<PeerId, Scalar>,
}

impl DkgG2 {
    fn new(num_peers: NumPeers, identity: PeerId) -> Self {
        let polynomial = (0..num_peers.threshold())
            .map(|_| Scalar::random(&mut OsRng))
            .collect::<Vec<Scalar>>();

        let commitment = polynomial.iter().map(g2).collect::<Vec<G2Projective>>();

        DkgG2 {
            num_peers,
            identity,
            polynomial,
            hash_commitments: once((identity, commitment.consensus_hash_sha256())).collect(),
            commitments: once((identity, commitment)).collect(),
            sk_shares: BTreeMap::new(),
        }
    }

    fn commitment(&self) -> Vec<G2Projective> {
        self.polynomial.iter().map(g2).collect()
    }

    fn initial_message(&self) -> DkgMessageG2 {
        DkgMessageG2::Hash(self.commitment().consensus_hash_sha256())
    }

    /// Runs a single step of the DKG algorithm
    fn step(&mut self, peer: PeerId, msg: DkgMessageG2) -> anyhow::Result<DkgStepG2> {
        trace!(?peer, ?msg, "Running DKG G2 step");
        match msg {
            DkgMessageG2::Hash(hash) => {
                ensure!(
                    self.hash_commitments.insert(peer, hash).is_none(),
                    "DKG G2: peer {peer} sent us two hash commitments."
                );

                if self.hash_commitments.len() == self.num_peers.total() {
                    return Ok(DkgStepG2::Broadcast(DkgMessageG2::Commitment(
                        self.commitment(),
                    )));
                }
            }
            DkgMessageG2::Commitment(polynomial) => {
                ensure!(
                    *self.hash_commitments.get(&peer).with_context(|| format!(
                        "DKG G2: hash commitment not found for peer {peer}"
                    ))? == polynomial.consensus_hash_sha256(),
                    "DKG G2: polynomial commitment from peer {peer} is of wrong degree."
                );

                ensure!(
                    self.num_peers.threshold() == polynomial.len(),
                    "DKG G2: polynomial commitment from peer {peer} is of wrong degree."
                );

                ensure!(
                    self.commitments.insert(peer, polynomial).is_none(),
                    "DKG G2: peer {peer} sent us two commitments."
                );

                // Once everyone has send their commitments, send out the key shares...

                if self.commitments.len() == self.num_peers.total() {
                    let mut messages = vec![];

                    for peer in self.num_peers.peer_ids() {
                        let s = eval_poly_scalar(&self.polynomial, &scalar(&peer));

                        if peer == self.identity {
                            self.sk_shares.insert(self.identity, s);
                        } else {
                            messages.push((peer, DkgMessageG2::Share(s)));
                        }
                    }

                    return Ok(DkgStepG2::Messages(messages));
                }
            }
            DkgMessageG2::Share(s) => {
                let polynomial = self.commitments.get(&peer).with_context(|| {
                    format!("DKG G2: polynomial commitment not found for peer {peer}.")
                })?;

                let checksum: G2Projective = polynomial
                    .iter()
                    .zip((0..).map(|k| scalar(&self.identity).pow(&[k, 0, 0, 0])))
                    .map(|(c, x)| c * x)
                    .reduce(|a, b| a + b)
                    .expect("DKG G2: polynomial commitment from peer is empty.");

                ensure!(g2(&s) == checksum, "DKG G2: share from {peer} is invalid.");

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
                                .reduce(|a, b| a + b)
                                .expect("DKG G2: polynomial commitments are empty.")
                        })
                        .collect();

                    return Ok(DkgStepG2::Result((pks, sks)));
                }
            }
        }

        Ok(DkgStepG2::Messages(vec![]))
    }
}

/// Runs the DKG G2 algorithm with our peers. We do not handle any unexpected
/// messages and all peers are expected to be cooperative.
pub async fn run_dkg_g2(
    num_peers: NumPeers,
    identity: PeerId,
    connections: &DynP2PConnections<P2PMessage>,
) -> anyhow::Result<(Vec<G2Projective>, Scalar)> {
    let mut dkg = DkgG2::new(num_peers, identity);

    connections
        .send(
            Recipient::Everyone,
            P2PMessage::DkgG2(dkg.initial_message()),
        )
        .await;

    loop {
        for peer in num_peers.peer_ids().filter(|p| *p != identity) {
            let message = connections
                .receive_from_peer(peer)
                .await
                .context("Unexpected shutdown of p2p connections during dkg g2")?;

            let message = match message {
                P2PMessage::DkgG2(message) => message,
                _ => bail!("Received unexpected message during DKG G2: {message:?}"),
            };

            match dkg.step(peer, message)? {
                DkgStepG2::Broadcast(message) => {
                    connections
                        .send(Recipient::Everyone, P2PMessage::DkgG2(message))
                        .await;
                }
                DkgStepG2::Messages(messages) => {
                    for (peer, message) in messages {
                        connections
                            .send(Recipient::Peer(peer), P2PMessage::DkgG2(message))
                            .await;
                    }
                }
                DkgStepG2::Result(result) => {
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

enum DkgStepG2 {
    Broadcast(DkgMessageG2),
    Messages(Vec<(PeerId, DkgMessageG2)>),
    Result((Vec<G2Projective>, Scalar)),
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};

    use fedimint_core::{NumPeersExt, PeerId};
    use fedimint_server_core::config::{eval_poly_g2, g2};
    use group::Curve;

    use super::{DkgG2, DkgStepG2};

    #[test_log::test]
    fn test_dkg_g2() {
        let peers = (0..7_u16).map(PeerId::from).collect::<Vec<PeerId>>();

        let mut dkgs = peers
            .iter()
            .map(|peer| (*peer, DkgG2::new(peers.to_num_peers(), *peer)))
            .collect::<BTreeMap<PeerId, DkgG2>>();

        let mut steps = dkgs
            .iter()
            .map(|(peer, dkg)| (*peer, DkgStepG2::Broadcast(dkg.initial_message())))
            .collect::<VecDeque<(PeerId, DkgStepG2)>>();

        let mut keys = BTreeMap::new();

        while keys.len() < peers.len() {
            match steps.pop_front().unwrap() {
                (send_peer, DkgStepG2::Broadcast(message)) => {
                    for receive_peer in peers.iter().filter(|p| **p != send_peer) {
                        let step = dkgs
                            .get_mut(receive_peer)
                            .unwrap()
                            .step(send_peer, message.clone());

                        steps.push_back((*receive_peer, step.unwrap()));
                    }
                }
                (send_peer, DkgStepG2::Messages(messages)) => {
                    for (receive_peer, message) in messages {
                        let step = dkgs
                            .get_mut(&receive_peer)
                            .unwrap()
                            .step(send_peer, message);

                        steps.push_back((receive_peer, step.unwrap()));
                    }
                }
                (send_peer, DkgStepG2::Result(step_keys)) => {
                    keys.insert(send_peer, step_keys);
                }
            }
        }

        assert!(steps.is_empty());

        for (peer, (poly_g2, sks)) in keys {
            assert_eq!(poly_g2.len(), 5);
            assert_eq!(eval_poly_g2(&poly_g2, &peer), g2(&sks).to_affine());
        }
    }
}
