use std::io::Write;

use bitcoin_hashes::{sha256, Hash};
use parity_scale_codec::{Decode, Encode, IoReader};

use crate::conversion::to_peer_id;
use crate::data_provider::UnitData;
use crate::keychain::Keychain;
use crate::{Message, Recipient};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Hasher;

impl aleph_bft::Hasher for Hasher {
    type Hash = [u8; 32];

    fn hash(input: &[u8]) -> Self::Hash {
        let mut engine = sha256::HashEngine::default();
        engine
            .write_all(input)
            .expect("Writing to a hash engine cannot fail");

        sha256::Hash::from_engine(engine).to_byte_array()
    }
}

pub type NetworkData = aleph_bft::NetworkData<
    Hasher,
    UnitData,
    <Keychain as aleph_bft::Keychain>::Signature,
    <Keychain as aleph_bft::MultiKeychain>::PartialMultisignature,
>;

pub struct Network {
    network_data_receiver: async_channel::Receiver<Vec<u8>>,
    outgoing_message_sender: async_channel::Sender<(Message, Recipient)>,
}

impl Network {
    pub fn new(
        network_data_receiver: async_channel::Receiver<Vec<u8>>,
        outgoing_message_sender: async_channel::Sender<(Message, Recipient)>,
    ) -> Self {
        Self {
            network_data_receiver,
            outgoing_message_sender,
        }
    }
}

#[async_trait::async_trait]
impl aleph_bft::Network<NetworkData> for Network {
    fn send(&self, network_data: NetworkData, recipient: aleph_bft::Recipient) {
        // convert from aleph_bft::Recipient to session::Recipient
        let recipient = match recipient {
            aleph_bft::Recipient::Node(node_index) => Recipient::Peer(to_peer_id(node_index)),
            aleph_bft::Recipient::Everyone => Recipient::Everyone,
        };

        // since NetworkData does not implement Encodable we use
        // parity_scale_codec::Encode to serialize it such that Message can
        // implement Encodable
        self.outgoing_message_sender
            .try_send((Message::NetworkData(network_data.encode()), recipient))
            .ok();
    }

    async fn next_event(&mut self) -> Option<NetworkData> {
        // This limits the RAM consumption of a Unit to roughly 12kB
        const ITEM_LIMIT: usize = 100;
        const BYTE_LIMIT: usize = 10_000;

        while let Ok(network_data) = self.network_data_receiver.recv().await {
            if let Ok(network_data) = NetworkData::decode(&mut IoReader(&*network_data)) {
                // in order to bound the RAM consumption of a session we have to bound an
                // individual units size, hence the size of its attached unitdata in memory
                if network_data.included_data().iter().all(|unit_data| {
                    match unit_data {
                        UnitData::Signature(..) => true,
                        UnitData::Batch(items, ..) => {
                            // the lazy evaluation prevents overflow when summing over the item
                            // sizes
                            items.len() <= ITEM_LIMIT
                                && items.iter().all(|item| item.len() <= BYTE_LIMIT)
                                && items.iter().map(Vec::len).sum::<usize>() <= BYTE_LIMIT
                        }
                    }
                }) {
                    return Some(network_data);
                }
            }
        }
        // this prevents the aleph session from shutting down when the
        // network data sender is dropped by the message relay task
        std::future::pending::<Option<NetworkData>>().await
    }
}
