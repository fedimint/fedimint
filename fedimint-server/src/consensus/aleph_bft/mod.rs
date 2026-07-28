pub mod backup;
pub mod data_provider;
pub mod finalization_handler;
pub mod keychain;
pub mod network;
pub mod spawner;

use aleph_bft::NodeIndex;
use fedimint_core::PeerId;

/// Convert an aleph-bft `NodeIndex` into a `PeerId`, if it can represent one.
///
/// `NodeIndex` wraps a `usize` and its decoder accepts any `u64` verbatim, so
/// every index embedded in a message received from a peer is chosen by that
/// peer and may not correspond to any peer at all. Callers have to handle
/// `None` instead of panicking, since a panic in the consensus task shuts down
/// the entire node.
pub fn to_peer_id(node_index: NodeIndex) -> Option<PeerId> {
    u16::try_from(usize::from(node_index))
        .ok()
        .map(PeerId::from)
}

pub fn to_node_index(peer_id: PeerId) -> NodeIndex {
    usize::from(u16::from(peer_id)).into()
}

#[cfg(test)]
mod tests {
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
}
