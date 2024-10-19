use bitcoin_hashes::{sha256, Hash};
use fedimint_core::encoding::Encodable;
use fedimint_core::net::peers::{P2PConnections, Recipient};
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
    connections: P2PConnections,
}

impl Network {
    pub fn new(connections: P2PConnections) -> Self {
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

        // since NetworkData does not implement Encodable we use
        // parity_scale_codec::Encode to serialize it such that Message can
        // implement Encodable
        self.connections.send(recipient, network_data.encode());
    }

    async fn next_event(&mut self) -> Option<NetworkData> {
        while let Ok(message) = self.connections.receive().await {
            if let Ok(network_data) = NetworkData::decode(&mut IoReader(message.1.as_slice())) {
                // in order to bound the RAM consumption of a session we have to bound an
                // individual units size, hence the size of its attached unitdata in memory
                if network_data.included_data().iter().all(UnitData::is_valid) {
                    return Some(network_data);
                }
            }
        }
        // this prevents the aleph session from shutting down when the
        // network data sender is dropped by the message relay task
        std::future::pending().await
    }
}
