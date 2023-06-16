use aleph_bft::NodeIndex;
use fedimint_core::PeerId;

pub fn to_peer_id(node_index: NodeIndex) -> PeerId {
    u16::try_from(usize::from(node_index))
        .expect("The node index corresponds to a valid PeerId")
        .into()
}

pub fn to_node_index(peer_id: PeerId) -> NodeIndex {
    usize::from(u16::from(peer_id)).into()
}
