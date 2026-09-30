use aleph_bft::NodeIndex;
use fedimint_core::PeerId;

use super::{to_node_index, to_peer_id};

#[test]
fn to_peer_id_roundtrips_valid_indices() {
    for peer_id in [PeerId::from(0), PeerId::from(3), PeerId::from(u16::MAX)] {
        assert_eq!(to_peer_id(to_node_index(peer_id)), Some(peer_id));
    }
}

#[test]
fn to_peer_id_rejects_out_of_range_indices() {
    // A malicious peer can embed an arbitrary u64 in a message it sends us, so
    // this must not panic and take the consensus session down with it.
    for index in [usize::from(u16::MAX) + 1, u32::MAX as usize, usize::MAX] {
        assert_eq!(to_peer_id(NodeIndex(index)), None);
    }
}
