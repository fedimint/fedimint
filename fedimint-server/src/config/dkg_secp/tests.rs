use std::collections::{BTreeMap, VecDeque};

use bip445::MAX_PARTICIPANTS;
use fedimint_core::{NumPeers, PeerId};
use rand::rngs::OsRng;
use secp256k1::{PublicKey, SECP256K1, SecretKey};

use super::{DkgSecp, DkgStepSecp, eval_poly};

/// Delivers the messages of the DKG instances among each other until every
/// instance has produced its keys.
fn run(
    num_peers: NumPeers,
    mut dkgs: BTreeMap<PeerId, DkgSecp>,
) -> BTreeMap<PeerId, (Vec<PublicKey>, SecretKey)> {
    let mut steps = dkgs
        .iter()
        .map(|(peer, dkg)| (*peer, DkgStepSecp::Broadcast(dkg.initial_message())))
        .collect::<VecDeque<(PeerId, DkgStepSecp)>>();

    let mut keys = BTreeMap::new();

    while keys.len() < num_peers.total() {
        match steps.pop_front().unwrap() {
            (send_peer, DkgStepSecp::Broadcast(message)) => {
                for receive_peer in num_peers.peer_ids().filter(|p| *p != send_peer) {
                    let step = dkgs
                        .get_mut(&receive_peer)
                        .unwrap()
                        .step(send_peer, message.clone());

                    steps.push_back((receive_peer, step.unwrap()));
                }
            }
            (send_peer, DkgStepSecp::Messages(messages)) => {
                for (receive_peer, message) in messages {
                    let step = dkgs
                        .get_mut(&receive_peer)
                        .unwrap()
                        .step(send_peer, message);

                    steps.push_back((receive_peer, step.unwrap()));
                }
            }
            (send_peer, DkgStepSecp::Result(step_keys)) => {
                keys.insert(send_peer, step_keys);
            }
        }
    }

    assert!(steps.is_empty());

    keys
}

/// Every peer's key share has to match the aggregate commitment, and all
/// peers have to agree on that commitment.
fn assert_consistent(num_peers: NumPeers, keys: &BTreeMap<PeerId, (Vec<PublicKey>, SecretKey)>) {
    let commitment = &keys.values().next().unwrap().0;

    assert_eq!(commitment.len(), num_peers.threshold());

    for (peer, (polynomial, sks)) in keys {
        assert_eq!(polynomial, commitment);
        assert_eq!(
            eval_poly(polynomial, peer).unwrap(),
            sks.public_key(SECP256K1)
        );
    }
}

#[test_log::test]
fn test_dkg_secp() {
    let num_peers = NumPeers::from(7);

    let dkgs = num_peers
        .peer_ids()
        .map(|peer| (peer, DkgSecp::new(num_peers, peer).unwrap()))
        .collect();

    assert_consistent(num_peers, &run(num_peers, dkgs));
}

/// Two colluding peers contribute a polynomial and its negation. Every share
/// verifies against its commitment, but their contributions sum to zero, so
/// the DKG has to tolerate an intermediate sum of zero and an intermediate
/// point at infinity instead of panicking.
#[test_log::test]
fn test_dkg_secp_cancelling_contributions() {
    let num_peers = NumPeers::from(7);

    let polynomial = (0..num_peers.threshold())
        .map(|_| SecretKey::new(&mut OsRng))
        .collect::<Vec<SecretKey>>();

    let negated = polynomial.iter().map(|c| c.negate()).collect();

    let mut peers = num_peers.peer_ids();

    let first = peers.next().unwrap();
    let second = peers.next().unwrap();

    let mut dkgs = BTreeMap::new();

    dkgs.insert(
        first,
        DkgSecp::with_polynomial(num_peers, first, polynomial).unwrap(),
    );

    dkgs.insert(
        second,
        DkgSecp::with_polynomial(num_peers, second, negated).unwrap(),
    );

    for peer in peers {
        dkgs.insert(peer, DkgSecp::new(num_peers, peer).unwrap());
    }

    assert_consistent(num_peers, &run(num_peers, dkgs));
}

#[test]
fn test_participant_bound() {
    let identity = NumPeers::from(1).peer_ids().next().unwrap();

    assert!(DkgSecp::new(NumPeers::from(MAX_PARTICIPANTS), identity).is_ok());
    assert!(DkgSecp::new(NumPeers::from(MAX_PARTICIPANTS + 1), identity).is_err());
}
