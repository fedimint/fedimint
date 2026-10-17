use std::collections::{BTreeMap, BTreeSet};

use super::{EmptyPeerSet, NumPeers, NumPeersExt, PeerId};

#[test]
fn num_peers_rejects_zero() {
    assert_eq!(NumPeers::new(0), None);
    assert_eq!(
        BTreeMap::<_, usize>::new().try_num_peers(),
        Err(EmptyPeerSet)
    );
    assert_eq!(Vec::<PeerId>::new().try_num_peers(), Err(EmptyPeerSet));
    assert_eq!(<&[PeerId]>::default().try_num_peers(), Err(EmptyPeerSet));
    assert_eq!(BTreeSet::<PeerId>::new().try_num_peers(), Err(EmptyPeerSet));
    assert_eq!(
        Vec::<crate::config::PeerUrl>::new().try_num_peers(),
        Err(EmptyPeerSet)
    );
}

/// An existing downstream implementation need only implement `to_num_peers`.
struct LegacyPeerCollection;

impl NumPeersExt for LegacyPeerCollection {
    fn to_num_peers(&self) -> NumPeers {
        NumPeers::from(4)
    }
}

#[test]
fn legacy_conversions_and_implementations_remain_source_compatible() {
    let peers: NumPeers = 4usize.into();
    assert_eq!(peers.total(), 4);
    let peers: NumPeers = LegacyPeerCollection.into();
    assert_eq!(peers.total(), 4);
    assert_eq!(
        LegacyPeerCollection.try_num_peers(),
        NumPeers::new(4).ok_or(EmptyPeerSet)
    );
    let peers: NumPeers = vec![PeerId::from(0)].into();
    assert_eq!(peers.total(), 1);
}

#[test]
#[should_panic(expected = "a federation must have at least one guardian")]
fn legacy_raw_conversion_rejects_zero() {
    let _ = NumPeers::from(0);
}

#[test]
#[should_panic(expected = "a federation must have at least one guardian")]
fn legacy_collection_conversion_rejects_empty() {
    let _ = NumPeers::from(Vec::<PeerId>::new());
}

#[test]
fn num_peers_quorum_parameters_match_positive_federations() {
    for (total, max_evil, one_honest, degree, threshold) in [
        (1, 0, 1, 0, 1),
        (2, 0, 1, 1, 2),
        (3, 0, 1, 2, 3),
        (4, 1, 2, 2, 3),
        (5, 1, 2, 3, 4),
        (6, 1, 2, 4, 5),
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
