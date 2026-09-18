use std::collections::{BTreeMap, BTreeSet};

use super::{NumPeers, NumPeersExt, PeerId};

#[test]
fn test_num_peers_zero_does_not_underflow() {
    let zero = NumPeers::from(0);
    assert_eq!(zero.total(), 0);
    assert_eq!(zero.max_evil(), 0);
    assert_eq!(zero.threshold(), 0);
    assert_eq!(zero.degree(), 0);
    assert_eq!(zero.one_honest(), 1);
}

#[test]
fn test_empty_collections_to_num_peers() {
    let empty_vec: Vec<PeerId> = Vec::new();
    assert_eq!(empty_vec.to_num_peers().max_evil(), 0);
    assert_eq!(empty_vec.to_num_peers().threshold(), 0);

    let empty_map: BTreeMap<PeerId, ()> = BTreeMap::new();
    assert_eq!(empty_map.to_num_peers().max_evil(), 0);
    assert_eq!(empty_map.to_num_peers().threshold(), 0);

    let empty_set: BTreeSet<PeerId> = BTreeSet::new();
    assert_eq!(empty_set.to_num_peers().max_evil(), 0);
    assert_eq!(empty_set.to_num_peers().threshold(), 0);
}

#[test]
fn test_num_peers_standard_topologies() {
    // 1 peer: f = 0, threshold = 1, degree = 0
    let one = NumPeers::from(1);
    assert_eq!(one.max_evil(), 0);
    assert_eq!(one.threshold(), 1);
    assert_eq!(one.degree(), 0);

    // 4 peers: f = 1, threshold = 3, degree = 2
    let four = NumPeers::from(4);
    assert_eq!(four.max_evil(), 1);
    assert_eq!(four.threshold(), 3);
    assert_eq!(four.degree(), 2);

    // 7 peers: f = 2, threshold = 5, degree = 4
    let seven = NumPeers::from(7);
    assert_eq!(seven.max_evil(), 2);
    assert_eq!(seven.threshold(), 5);
    assert_eq!(seven.degree(), 4);

    // 10 peers: f = 3, threshold = 7, degree = 6
    let ten = NumPeers::from(10);
    assert_eq!(ten.max_evil(), 3);
    assert_eq!(ten.threshold(), 7);
    assert_eq!(ten.degree(), 6);
}
