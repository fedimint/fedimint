use aleph_bft::Keychain as KeychainTrait;
use bitcoin_hashes::{sha256, Hash};
use fedimint_core::encoding::Encodable;
use tokio::sync::watch;

use crate::keychain::Keychain;

type ConsensusItem = Vec<u8>;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, parity_scale_codec::Encode, parity_scale_codec::Decode,
)]
pub enum UnitData {
    Batch(Vec<ConsensusItem>, [u8; 64], aleph_bft::NodeIndex),
    Signature([u8; 64], aleph_bft::NodeIndex),
}

pub struct DataProvider {
    keychain: Keychain,
    mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
    signature_receiver: watch::Receiver<Option<[u8; 64]>>,
    item: Option<Vec<u8>>,
}

impl DataProvider {
    pub fn new(
        keychain: Keychain,
        mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
        signature_receiver: watch::Receiver<Option<[u8; 64]>>,
    ) -> Self {
        Self {
            keychain,
            mempool_item_receiver,
            signature_receiver,
            item: None,
        }
    }
}

#[async_trait::async_trait]
impl aleph_bft::DataProvider<UnitData> for DataProvider {
    async fn get_data(&mut self) -> Option<UnitData> {
        // This function constructs UnitData such that it is accepted by the Network
        // implementation
        const ITEM_LIMIT: usize = 100;
        const BYTE_LIMIT: usize = 10_000;

        // we only attach our signature as no more items can be ordered in this session
        if let Some(signature) = self.signature_receiver.borrow().clone() {
            return Some(UnitData::Signature(signature, self.keychain.peer_id.into()));
        }

        let mut n_items = 0;
        let mut batch_size = 0;
        let mut items = vec![];

        if let Some(bytes) = self.item.take() {
            // if the stored item is larger then the BYTE_LIMIT we discard it
            if bytes.len() <= BYTE_LIMIT {
                n_items += 1;
                batch_size += bytes.len();
                items.push(bytes);
            }
        }

        while let Ok(item) = self.mempool_item_receiver.try_recv() {
            if n_items + 1 <= ITEM_LIMIT && batch_size + item.len() <= BYTE_LIMIT {
                n_items += 1;
                batch_size += item.len();
                items.push(item);
            } else {
                self.item = Some(item);
                break;
            }
        }

        // enables us to verify which peer has submitted a item
        let mut engine = sha256::HashEngine::default();
        items
            .consensus_encode(&mut engine)
            .expect("Writing to HashEngine cannot fail");
        let hash = sha256::Hash::from_engine(engine);
        let signature = self.keychain.sign(hash.as_byte_array()).await;

        Some(UnitData::Batch(
            items,
            signature,
            self.keychain.peer_id.into(),
        ))
    }
}
