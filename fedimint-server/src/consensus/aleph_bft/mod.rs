pub mod backup;
pub mod data_provider;
pub mod finalization_handler;
pub mod keychain;
pub mod network;
pub mod spawner;

use aleph_bft::NodeIndex;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::PeerId;
use serde::{Deserialize, Serialize};

/// The majority of these messages need to be delivered to the intended
/// [Recipient] in order for aleph bft to make progress. However, alpeh bft does
/// not assume a reliable network layer and implements all necessary retry
/// logic. Therefore, the network layer can discard a message if its
/// intended recipient is offline.
#[derive(Clone, Debug, Encodable, Decodable, Serialize, Deserialize)]
pub struct Message(Vec<u8>);

/// This enum defines the intended recipient of a [Message].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    Everyone,
    Peer(PeerId),
}

pub fn to_peer_id(node_index: NodeIndex) -> PeerId {
    u16::try_from(usize::from(node_index))
        .expect("The node index corresponds to a valid PeerId")
        .into()
}

pub fn to_node_index(peer_id: PeerId) -> NodeIndex {
    usize::from(u16::from(peer_id)).into()
}
