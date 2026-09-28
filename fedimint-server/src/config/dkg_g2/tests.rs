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
