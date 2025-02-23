use bitcoin::hashes::{Hash, sha256};
use fedimint_core::config::P2PMessage;
use fedimint_core::encoding::Encodable;
use fedimint_core::net::peers::{DynP2PConnections, Recipient};
use parity_scale_codec::{Decode, Encode, IoReader};

use super::data_provider::UnitData;
use super::keychain::Keychain;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Hasher;

impl aleph_bft::Hasher for Hasher {
    type Hash = [u8; 32];

    fn hash(input: &[u8]) -> Self::Hash {
        input.consensus_hash::<sha256::Hash>().to_byte_array()
    }
}

pub type NetworkData = aleph_bft::NetworkData<
    Hasher,
    UnitData,
    <Keychain as aleph_bft::Keychain>::Signature,
    <Keychain as aleph_bft::MultiKeychain>::PartialMultisignature,
>;

pub struct Network {
    connections: DynP2PConnections<P2PMessage>,
}

impl Network {
    pub fn new(connections: DynP2PConnections<P2PMessage>) -> Self {
        Self { connections }
    }
}

#[async_trait::async_trait]
impl aleph_bft::Network<NetworkData> for Network {
    fn send(&self, network_data: NetworkData, recipient: aleph_bft::Recipient) {
        // convert from aleph_bft::Recipient to session::Recipient
        let recipient = match recipient {
            aleph_bft::Recipient::Node(node_index) => {
                Recipient::Peer(super::to_peer_id(node_index))
            }
            aleph_bft::Recipient::Everyone => Recipient::Everyone,
        };

        self.connections
            .try_send(recipient, P2PMessage::Aleph(network_data.encode()));
    }

    async fn next_event(&mut self) -> Option<NetworkData> {
        loop {
            if let P2PMessage::Aleph(bytes) = self.connections.receive().await?.1 {
                if let Ok(network_data) = NetworkData::decode(&mut IoReader(bytes.as_slice())) {
                    // in order to bound the RAM consumption of a session we have to bound an
                    // individual units size, hence the size of its attached unitdata in memory
                    if network_data.included_data().iter().all(UnitData::is_valid) {
                        return Some(network_data);
                    }
                }
            }
        }
    }
}
