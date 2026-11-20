use std::collections::BTreeMap;
use std::iter::once;

use anyhow::{Context, bail, ensure};
use fedimint_core::bitcoin::hashes::sha256;
use fedimint_core::config::{DkgMessageSecp, P2PMessage};
use fedimint_core::encoding::Encodable as _;
use fedimint_core::net::{DynP2PConnections, Recipient};
use fedimint_core::{NumPeers, PeerId};
use fedimint_server_core::config::{eval_poly_secp, scalar_secp};
use rand::rngs::OsRng;
use secp256k1::{PublicKey, SECP256K1, Scalar, SecretKey};
use tracing::trace;

// Implementation of the classic Pedersen DKG over secp256k1.

struct DkgSecp {
    num_peers: NumPeers,
    identity: PeerId,
    polynomial: Vec<SecretKey>,
    hash_commitments: BTreeMap<PeerId, sha256::Hash>,
    commitments: BTreeMap<PeerId, Vec<PublicKey>>,
    sk_shares: BTreeMap<PeerId, SecretKey>,
}

impl DkgSecp {
    fn new(num_peers: NumPeers, identity: PeerId) -> Self {
        let polynomial = (0..num_peers.threshold())
            .map(|_| SecretKey::new(&mut OsRng))
            .collect::<Vec<SecretKey>>();

        let commitment = polynomial
            .iter()
            .map(|coefficient| coefficient.public_key(SECP256K1))
            .collect::<Vec<PublicKey>>();

        DkgSecp {
            num_peers,
            identity,
            polynomial,
            hash_commitments: once((identity, commitment.consensus_hash_sha256())).collect(),
            commitments: once((identity, commitment)).collect(),
            sk_shares: BTreeMap::new(),
        }
    }

    fn commitment(&self) -> Vec<PublicKey> {
        self.polynomial
            .iter()
            .map(|coefficient| coefficient.public_key(SECP256K1))
            .collect()
    }

    fn initial_message(&self) -> DkgMessageSecp {
        DkgMessageSecp::Hash(self.commitment().consensus_hash_sha256())
    }

    /// Runs a single step of the DKG algorithm
    fn step(&mut self, peer: PeerId, msg: DkgMessageSecp) -> anyhow::Result<DkgStepSecp> {
        trace!(?peer, ?msg, "Running DKG secp step");
        match msg {
            DkgMessageSecp::Hash(hash) => {
                ensure!(
                    self.hash_commitments.insert(peer, hash).is_none(),
                    "DKG secp: peer {peer} sent us two hash commitments."
                );

                if self.hash_commitments.len() == self.num_peers.total() {
                    return Ok(DkgStepSecp::Broadcast(DkgMessageSecp::Commitment(
                        self.commitment(),
                    )));
                }
            }
            DkgMessageSecp::Commitment(polynomial) => {
                ensure!(
                    *self.hash_commitments.get(&peer).with_context(|| format!(
                        "DKG secp: hash commitment not found for peer {peer}"
                    ))? == polynomial.consensus_hash_sha256(),
                    "DKG secp: polynomial commitment from peer {peer} does not match the hash."
                );

                ensure!(
                    self.num_peers.threshold() == polynomial.len(),
                    "DKG secp: polynomial commitment from peer {peer} is of wrong degree."
                );

                ensure!(
                    self.commitments.insert(peer, polynomial).is_none(),
                    "DKG secp: peer {peer} sent us two commitments."
                );

                // Once everyone has send their commitments, send out the key shares...

                if self.commitments.len() == self.num_peers.total() {
                    let mut messages = vec![];

                    for peer in self.num_peers.peer_ids() {
                        let share = eval_poly_scalar(&self.polynomial, &scalar_secp(&peer));

                        if peer == self.identity {
                            self.sk_shares.insert(self.identity, share);
                        } else {
                            messages.push((peer, DkgMessageSecp::Share(share)));
                        }
                    }

                    return Ok(DkgStepSecp::Messages(messages));
                }
            }
            DkgMessageSecp::Share(share) => {
                let polynomial = self.commitments.get(&peer).with_context(|| {
                    format!("DKG secp: polynomial commitment not found for peer {peer}.")
                })?;

                let checksum = eval_poly_secp(polynomial, &self.identity)?;

                ensure!(
                    share.public_key(SECP256K1) == checksum,
                    "DKG secp: share from {peer} is invalid."
                );

                ensure!(
                    self.sk_shares.insert(peer, share).is_none(),
                    "Peer {peer} sent us two sk shares."
                );

                if self.sk_shares.len() == self.num_peers.total() {
                    let sks = self
                        .sk_shares
                        .values()
                        .copied()
                        .reduce(|accumulator, share| {
                            accumulator.add_tweak(&key_scalar(&share)).expect(
                                "The shares are hash-committed, an intermediate sum of zero is negligible",
                            )
                        })
                        .expect("We have at least one share");

                    let pks = (0..self.num_peers.threshold())
                        .map(|i| {
                            self.commitments
                                .values()
                                .map(|coefficients| coefficients[i])
                                .reduce(|accumulator, coefficient| {
                                    accumulator.combine(&coefficient).expect(
                                        "The coefficients are hash-committed, a sum at infinity is negligible",
                                    )
                                })
                                .expect("DKG secp: polynomial commitments are empty.")
                        })
                        .collect();

                    return Ok(DkgStepSecp::Result((pks, sks)));
                }
            }
        }

        Ok(DkgStepSecp::Messages(vec![]))
    }
}

/// Runs the DKG secp algorithm with our peers. We do not handle any unexpected
/// messages and all peers are expected to be cooperative.
pub async fn run_dkg_secp(
    num_peers: NumPeers,
    identity: PeerId,
    connections: &DynP2PConnections<P2PMessage>,
) -> anyhow::Result<(Vec<PublicKey>, SecretKey)> {
    let mut dkg = DkgSecp::new(num_peers, identity);

    connections.send(
        Recipient::Everyone,
        P2PMessage::DkgSecp(dkg.initial_message()),
    );

    loop {
        for peer in num_peers.peer_ids().filter(|p| *p != identity) {
            let message = connections
                .receive_from_peer(peer)
                .await
                .context("Unexpected shutdown of p2p connections during dkg secp")?;

            let message = match message {
                P2PMessage::DkgSecp(message) => message,
                _ => bail!("Received unexpected message during DKG secp: {message:?}"),
            };

            match dkg.step(peer, message)? {
                DkgStepSecp::Broadcast(message) => {
                    connections.send(Recipient::Everyone, P2PMessage::DkgSecp(message));
                }
                DkgStepSecp::Messages(messages) => {
                    for (peer, message) in messages {
                        connections.send(Recipient::Peer(peer), P2PMessage::DkgSecp(message));
                    }
                }
                DkgStepSecp::Result(result) => {
                    return Ok(result);
                }
            }
        }
    }
}

fn key_scalar(key: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(key.secret_bytes()).expect("A secret key is a valid scalar")
}

fn eval_poly_scalar(coefficients: &[SecretKey], x: &Scalar) -> SecretKey {
    coefficients
        .iter()
        .copied()
        .rev()
        .reduce(|accumulator, coefficient| {
            accumulator
                .mul_tweak(x)
                .expect("The evaluation point is nonzero")
                .add_tweak(&key_scalar(&coefficient))
                .expect("An intermediate value of our random polynomial is zero with negligible probability")
        })
        .expect("We have at least one coefficient")
}

enum DkgStepSecp {
    Broadcast(DkgMessageSecp),
    Messages(Vec<(PeerId, DkgMessageSecp)>),
    Result((Vec<PublicKey>, SecretKey)),
}

#[cfg(test)]
mod tests;
