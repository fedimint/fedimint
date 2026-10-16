use std::collections::{BTreeMap, VecDeque};

use fedimint_core::{NumPeersExt, PeerId};
use fedimint_server_core::config::{eval_poly_g1, g1};
use group::Curve;

use super::{DkgG1, DkgStepG1};

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
                    let step = dkgs
                        .get_mut(receive_peer)
                        .unwrap()
                        .step(send_peer, message.clone());

                    steps.push_back((*receive_peer, step.unwrap()));
                }
            }
            (send_peer, DkgStepG1::Messages(messages)) => {
                for (receive_peer, message) in messages {
                    let step = dkgs
                        .get_mut(&receive_peer)
                        .unwrap()
                        .step(send_peer, message);

                    steps.push_back((receive_peer, step.unwrap()));
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
