use std::collections::{BTreeMap, VecDeque};

use fedimint_core::{NumPeers, PeerId};
use secp256k1::SECP256K1;

use super::{DkgSecp, DkgStepSecp, eval_poly};

#[test_log::test]
fn test_dkg_secp() {
    let num_peers = NumPeers::from(7);

    let mut dkgs = num_peers
        .peer_ids()
        .map(|peer| (peer, DkgSecp::new(num_peers, peer)))
        .collect::<BTreeMap<PeerId, DkgSecp>>();

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

    for (peer, (polynomial, sks)) in keys {
        assert_eq!(polynomial.len(), 5);
        assert_eq!(
            eval_poly(&polynomial, &peer).unwrap(),
            sks.public_key(SECP256K1)
        );
    }
}
