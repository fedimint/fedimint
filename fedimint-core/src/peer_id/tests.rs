use std::collections::BTreeMap;

use super::{EmptyPeerSet, NumPeers, NumPeersExt as _};

#[test]
fn num_peers_rejects_zero() {
    assert_eq!(NumPeers::new(0), None);
    assert_eq!(NumPeers::try_from(0), Err(EmptyPeerSet));
    assert_eq!(
        BTreeMap::<_, usize>::new().try_num_peers(),
        Err(EmptyPeerSet)
    );
}

#[test]
fn num_peers_quorum_parameters_match_positive_federations() {
    for (total, max_evil, one_honest, degree, threshold) in [
        (1, 0, 1, 0, 1),
        (4, 1, 2, 2, 3),
        (7, 2, 3, 4, 5),
        (10, 3, 4, 6, 7),
    ] {
        let peers = NumPeers::new(total).expect("test peer count is nonzero");

        assert_eq!(peers.total(), total);
        assert_eq!(peers.max_evil(), max_evil);
        assert_eq!(peers.one_honest(), one_honest);
        assert_eq!(peers.degree(), degree);
        assert_eq!(peers.threshold(), threshold);
    }
}
