pub mod backup;
pub mod data_provider;
pub mod finalization_handler;
pub mod keychain;
pub mod network;
pub mod spawner;

use std::marker::PhantomData;

use aleph_bft::NodeIndex as AlephNodeIndex;
use fedimint_core::PeerId;

mod sealed {
    pub trait Sealed {}
}

pub trait NodeIndexValidation: sealed::Sealed {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Unchecked;

impl sealed::Sealed for Unchecked {}

impl NodeIndexValidation for Unchecked {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PeerIdRangeChecked;

impl sealed::Sealed for PeerIdRangeChecked {}

impl NodeIndexValidation for PeerIdRangeChecked {}

/// An Aleph BFT node index branded by its validation state.
///
/// Aleph's `NodeIndex` wraps a `usize` and its decoder accepts any `u64`
/// verbatim, so every index embedded in a message received from a peer is
/// chosen by that peer. Code must not convert an unchecked index into a
/// `PeerId`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NodeIndex<V: NodeIndexValidation = PeerIdRangeChecked> {
    inner: AlephNodeIndex,
    validation: PhantomData<V>,
}

impl NodeIndex<Unchecked> {
    pub fn from_aleph(inner: AlephNodeIndex) -> Self {
        Self {
            inner,
            validation: PhantomData,
        }
    }

    pub fn validate_peer_id_range(self) -> Option<NodeIndex<PeerIdRangeChecked>> {
        u16::try_from(usize::from(self.inner))
            .ok()
            .map(|_| NodeIndex {
                inner: self.inner,
                validation: PhantomData,
            })
    }
}

impl NodeIndex<PeerIdRangeChecked> {
    fn to_peer_id(self) -> PeerId {
        u16::try_from(usize::from(self.inner))
            .expect("NodeIndex<PeerIdRangeChecked> represents a valid PeerId")
            .into()
    }
}

/// Convert a checked aleph-bft node index into a `PeerId`.
pub fn to_peer_id(node_index: NodeIndex<PeerIdRangeChecked>) -> PeerId {
    node_index.to_peer_id()
}

pub fn to_node_index(peer_id: PeerId) -> AlephNodeIndex {
    usize::from(u16::from(peer_id)).into()
}

#[cfg(test)]
mod tests {
    use aleph_bft::NodeIndex as AlephNodeIndex;
    use fedimint_core::PeerId;

    use super::{NodeIndex, Unchecked, to_node_index, to_peer_id};

    #[test]
    fn to_peer_id_roundtrips_valid_indices() {
        for peer_id in [PeerId::from(0), PeerId::from(3), PeerId::from(u16::MAX)] {
            let node_index =
                NodeIndex::<Unchecked>::from_aleph(to_node_index(peer_id)).validate_peer_id_range();

            assert_eq!(node_index.map(to_peer_id), Some(peer_id));
        }
    }

    #[test]
    fn to_peer_id_rejects_out_of_range_indices() {
        // A malicious peer can embed an arbitrary u64 in a message it sends us, so
        // this must not panic and take the consensus session down with it.
        for index in [usize::from(u16::MAX) + 1, u32::MAX as usize, usize::MAX] {
            assert_eq!(
                NodeIndex::<Unchecked>::from_aleph(AlephNodeIndex(index)).validate_peer_id_range(),
                None
            );
        }
    }
}
