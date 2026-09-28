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
mod tests;
