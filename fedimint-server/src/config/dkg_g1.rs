use std::collections::BTreeMap;
use std::iter::once;

use anyhow::{Context, bail, ensure};
use bls12_381::{G1Projective, Scalar};
use fedimint_core::bitcoin::hashes::sha256;
use fedimint_core::config::{DkgMessageG1, P2PMessage};
use fedimint_core::encoding::Encodable as _;
use fedimint_core::net::peers::{DynP2PConnections, Recipient};
use fedimint_core::{NumPeers, PeerId};
use fedimint_server_core::config::{eval_poly_scalar, g1, scalar};
use group::ff::Field;
use rand::rngs::OsRng;
use tracing::trace;

// Implementation of the classic Pedersen DKG for G1.

struct DkgG1 {
    num_peers: NumPeers,
    identity: PeerId,
    polynomial: Vec<Scalar>,
    hash_commitments: BTreeMap<PeerId, sha256::Hash>,
    commitments: BTreeMap<PeerId, Vec<G1Projective>>,
    sk_shares: BTreeMap<PeerId, Scalar>,
    commitment_sent: bool,
    shares_sent: bool,
    finished: bool,
}

impl DkgG1 {
    fn new(num_peers: NumPeers, identity: PeerId) -> Self {
        let polynomial = (0..num_peers.threshold())
            .map(|_| Scalar::random(&mut OsRng))
            .collect::<Vec<Scalar>>();

        let commitment = polynomial.iter().map(g1).collect::<Vec<G1Projective>>();

        DkgG1 {
            num_peers,
            identity,
            polynomial,
            hash_commitments: once((identity, commitment.consensus_hash_sha256())).collect(),
            commitments: once((identity, commitment)).collect(),
            sk_shares: BTreeMap::new(),
            commitment_sent: false,
            shares_sent: false,
            finished: false,
        }
    }

    fn commitment(&self) -> Vec<G1Projective> {
        self.polynomial.iter().map(g1).collect()
    }

    fn initial_message(&self) -> DkgMessageG1 {
        DkgMessageG1::Hash(self.commitment().consensus_hash_sha256())
    }

    /// Records a message received from `peer`. Any resulting protocol
    /// transitions are produced by [`DkgG1::advance`].
    fn step(&mut self, peer: PeerId, msg: DkgMessageG1) -> anyhow::Result<()> {
        trace!(?peer, ?msg, "Running DKG G1 step");
        match msg {
            DkgMessageG1::Hash(hash) => {
                ensure!(
                    self.hash_commitments.insert(peer, hash).is_none(),
                    "DKG G1: peer {peer} sent us two hash commitments."
                );
            }
            DkgMessageG1::Commitment(polynomial) => {
                ensure!(
                    *self.hash_commitments.get(&peer).with_context(|| format!(
                        "DKG G1: hash commitment not found for peer {peer}"
                    ))? == polynomial.consensus_hash_sha256(),
                    "DKG G1: polynomial commitment from peer {peer} is of wrong degree."
                );

                ensure!(
                    self.num_peers.threshold() == polynomial.len(),
                    "DKG G1: polynomial commitment from peer {peer} is of wrong degree."
                );

                ensure!(
                    self.commitments.insert(peer, polynomial).is_none(),
                    "DKG G1: peer {peer} sent us two commitments."
                );
            }
            DkgMessageG1::Share(s) => {
                let polynomial = self.commitments.get(&peer).with_context(|| {
                    format!("DKG G1: polynomial commitment not found for peer {peer}.")
                })?;

                let checksum: G1Projective = polynomial
                    .iter()
                    .zip((0..).map(|k| scalar(&self.identity).pow(&[k, 0, 0, 0])))
                    .map(|(c, x)| c * x)
                    .reduce(|a, b| a + b)
                    .expect("DKG G1: polynomial commitment from peer is empty.");

                ensure!(g1(&s) == checksum, "DKG G1: share from {peer} is invalid.");

                ensure!(
                    self.sk_shares.insert(peer, s).is_none(),
                    "Peer {peer} sent us two sk shares."
                );
            }
        }

        Ok(())
    }

    /// Returns the next protocol transition that our current state enables, or
    /// `None` if we have to wait for further messages from our peers.
    ///
    /// The transitions are checked against the state we have accumulated so far
    /// rather than against the message that just arrived, so a federation of a
    /// single guardian - which never receives any message - runs the protocol
    /// to completion by repeatedly calling this method.
    fn advance(&mut self) -> Option<DkgStepG1> {
        if self.finished {
            return None;
        }

        if self.sk_shares.len() == self.num_peers.total() {
            self.finished = true;

            let sks = self.sk_shares.values().sum();

            let pks = (0..self.num_peers.threshold())
                .map(|i| {
                    self.commitments
                        .values()
                        .map(|coefficients| coefficients[i])
                        .reduce(|a, b| a + b)
                        .expect("DKG G1: polynomial commitments are empty.")
                })
                .collect();

            return Some(DkgStepG1::Result((pks, sks)));
        }

        // Once everyone has sent their commitments, send out the key shares...

        if !self.shares_sent && self.commitments.len() == self.num_peers.total() {
            self.shares_sent = true;

            let mut messages = vec![];

            for peer in self.num_peers.peer_ids() {
                let s = eval_poly_scalar(&self.polynomial, &scalar(&peer));

                if peer == self.identity {
                    self.sk_shares.insert(self.identity, s);
                } else {
                    messages.push((peer, DkgMessageG1::Share(s)));
                }
            }

            return Some(DkgStepG1::Messages(messages));
        }

        if !self.commitment_sent && self.hash_commitments.len() == self.num_peers.total() {
            self.commitment_sent = true;

            return Some(DkgStepG1::Broadcast(DkgMessageG1::Commitment(
                self.commitment(),
            )));
        }

        None
    }
}

/// Runs the DKG G1 algorithm with our peers. We do not handle any unexpected
/// messages and all peers are expected to be cooperative.
pub async fn run_dkg_g1(
    num_peers: NumPeers,
    identity: PeerId,
    connections: &DynP2PConnections<P2PMessage>,
) -> anyhow::Result<(Vec<G1Projective>, Scalar)> {
    let mut dkg = DkgG1::new(num_peers, identity);

    connections.send(
        Recipient::Everyone,
        P2PMessage::DkgG1(dkg.initial_message()),
    );

    // A federation of a single guardian has nobody to hear from, so the
    // protocol runs to completion right here.
    if let Some(result) = drive(&mut dkg, connections) {
        return Ok(result);
    }

    loop {
        for peer in num_peers.peer_ids().filter(|p| *p != identity) {
            let message = connections
                .receive_from_peer(peer)
                .await
                .context("Unexpected shutdown of p2p connections during dkg g1")?;

            let message = match message {
                P2PMessage::DkgG1(message) => message,
                _ => bail!("Received unexpected message during DKG G1: {message:?}"),
            };

            dkg.step(peer, message)?;

            if let Some(result) = drive(&mut dkg, connections) {
                return Ok(result);
            }
        }
    }
}

/// Runs every protocol transition our current state enables, sending the
/// resulting messages to our peers. Returns the DKG result once we reach it.
fn drive(
    dkg: &mut DkgG1,
    connections: &DynP2PConnections<P2PMessage>,
) -> Option<(Vec<G1Projective>, Scalar)> {
    while let Some(step) = dkg.advance() {
        match step {
            DkgStepG1::Broadcast(message) => {
                connections.send(Recipient::Everyone, P2PMessage::DkgG1(message));
            }
            DkgStepG1::Messages(messages) => {
                for (peer, message) in messages {
                    connections.send(Recipient::Peer(peer), P2PMessage::DkgG1(message));
                }
            }
            DkgStepG1::Result(result) => {
                return Some(result);
            }
        }
    }

    None
}

enum DkgStepG1 {
    Broadcast(DkgMessageG1),
    Messages(Vec<(PeerId, DkgMessageG1)>),
    Result((Vec<G1Projective>, Scalar)),
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};

    use fedimint_core::{NumPeersExt, PeerId};
    use fedimint_server_core::config::{eval_poly_g1, g1};
    use group::Curve;

    use super::{DkgG1, DkgStepG1};

    /// Delivers `message` from `send_peer` to `receive_peer` and queues up
    /// every transition that unlocks as a result.
    fn deliver(
        dkgs: &mut BTreeMap<PeerId, DkgG1>,
        steps: &mut VecDeque<(PeerId, DkgStepG1)>,
        send_peer: PeerId,
        receive_peer: PeerId,
        message: fedimint_core::config::DkgMessageG1,
    ) {
        let dkg = dkgs.get_mut(&receive_peer).unwrap();

        dkg.step(send_peer, message).unwrap();

        while let Some(step) = dkg.advance() {
            steps.push_back((receive_peer, step));
        }
    }

    #[test_log::test]
    fn test_dkg_g1() {
        let peers = (0..7_u16).map(PeerId::from).collect::<Vec<PeerId>>();

        let mut dkgs = peers
            .iter()
            .map(|peer| (*peer, DkgG1::new(peers.to_num_peers(), *peer)))
            .collect::<BTreeMap<PeerId, DkgG1>>();

        let mut steps = dkgs
            .iter()
            .map(|(peer, dkg)| (*peer, DkgStepG1::Broadcast(dkg.initial_message())))
            .collect::<VecDeque<(PeerId, DkgStepG1)>>();

        let mut keys = BTreeMap::new();

        while keys.len() < peers.len() {
            match steps.pop_front().unwrap() {
                (send_peer, DkgStepG1::Broadcast(message)) => {
                    for receive_peer in peers.iter().filter(|p| **p != send_peer) {
                        deliver(
                            &mut dkgs,
                            &mut steps,
                            send_peer,
                            *receive_peer,
                            message.clone(),
                        );
                    }
                }
                (send_peer, DkgStepG1::Messages(messages)) => {
                    for (receive_peer, message) in messages {
                        deliver(&mut dkgs, &mut steps, send_peer, receive_peer, message);
                    }
                }
                (send_peer, DkgStepG1::Result(step_keys)) => {
                    keys.insert(send_peer, step_keys);
                }
            }
        }

        assert!(steps.is_empty());

        for (peer, (poly_g1, sks)) in keys {
            assert_eq!(poly_g1.len(), 5);
            assert_eq!(eval_poly_g1(&poly_g1, &peer), g1(&sks).to_affine());
        }
    }

    /// A single guardian receives no messages at all, so the protocol has to
    /// complete purely by advancing our own state. Before this was possible the
    /// production config generation fell back to a trusted dealer, which is how
    /// deterministic key material ended up in solo federations.
    #[test_log::test]
    fn test_dkg_g1_single_guardian() {
        let peers = vec![PeerId::from(0)];

        let run = || {
            let mut dkg = DkgG1::new(peers.to_num_peers(), PeerId::from(0));

            loop {
                match dkg.advance().expect("DKG stalled without any peers") {
                    DkgStepG1::Result(result) => return result,
                    DkgStepG1::Broadcast(_) | DkgStepG1::Messages(_) => {}
                }
            }
        };

        let (poly_g1, sks) = run();

        assert_eq!(poly_g1.len(), 1);
        assert_eq!(
            eval_poly_g1(&poly_g1, &PeerId::from(0)),
            g1(&sks).to_affine()
        );

        // The key must come from the OS RNG rather than being derived
        // deterministically.
        assert_ne!(sks, run().1);
    }
}
