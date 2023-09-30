use std::collections::BTreeSet;

use aleph_bft::Keychain as KeychainTrait;
use bitcoin_hashes_12::{sha256, Hash};
use fedimint_core::block::consensus_hash_sha256;
use tokio::sync::watch;

use super::keychain::Keychain;

type ConsensusItem = Vec<u8>;

// This limits the RAM consumption of a Unit to roughly 12kB
const ITEM_LIMIT: usize = 100;
const BYTE_LIMIT: usize = 10_000;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, parity_scale_codec::Encode, parity_scale_codec::Decode,
)]
pub enum UnitData {
    Batch(Vec<ConsensusItem>, [u8; 64], aleph_bft::NodeIndex),
    Signature([u8; 64], aleph_bft::NodeIndex),
}

impl UnitData {
    // in order to bound the RAM consumption of a session we have to bound an
    // individual units size, hence the size of its attached unit data in memory
    pub fn is_valid(&self) -> bool {
        match self {
            UnitData::Signature(..) => true,
            UnitData::Batch(items, ..) => {
                // the lazy evaluation prevents overflow when summing
                items.len() <= ITEM_LIMIT
                    && items.iter().all(|item| item.len() <= BYTE_LIMIT)
                    && items.iter().map(Vec::len).sum::<usize>() <= BYTE_LIMIT
            }
        }
    }
}

pub struct DataProvider {
    keychain: Keychain,
    mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
    signature_receiver: watch::Receiver<Option<[u8; 64]>>,
    submitted_items: BTreeSet<sha256::Hash>,
    leftover_item: Option<Vec<u8>>,
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
            submitted_items: BTreeSet::new(),
            leftover_item: None,
        }
    }
}

#[async_trait::async_trait]
impl aleph_bft::DataProvider<UnitData> for DataProvider {
    async fn get_data(&mut self) -> Option<UnitData> {
        // we only attach our signature as no more items can be ordered in this session
        if let Some(signature) = *self.signature_receiver.borrow() {
            return Some(UnitData::Signature(
                signature,
                self.keychain.peer_id().to_usize().into(),
            ));
        }

        let mut items = vec![];

        if let Some(item) = self.leftover_item.take() {
            if item.len() <= BYTE_LIMIT {
                if self.submitted_items.insert(consensus_hash_sha256(&item)) {
                    items.push(item);
                }
            } else {
                tracing::error!("Consensus item length is over BYTE_LIMIT");
            }
        }

        // if the channel is empty we want to return the batch immediately in order to
        // not delay the creation of our next unit, even if the batch is empty
        while let Ok(item) = self.mempool_item_receiver.try_recv() {
            let n_bytes = items.iter().map(Vec::len).sum::<usize>();

            #[allow(clippy::int_plus_one)]
            if items.len() + 1 <= ITEM_LIMIT && n_bytes + item.len() <= BYTE_LIMIT {
                if self.submitted_items.insert(consensus_hash_sha256(&item)) {
                    items.push(item);
                }
            } else {
                self.leftover_item = Some(item);
                break;
            }
        }

        // enables us to verify which peer has submitted a item
        let hash = consensus_hash_sha256(&items);
        let signature = self.keychain.sign(hash.as_byte_array()).await;

        let unit_data =
            UnitData::Batch(items, signature, self.keychain.peer_id().to_usize().into());

        assert!(unit_data.is_valid());

        Some(unit_data)
    }
}
