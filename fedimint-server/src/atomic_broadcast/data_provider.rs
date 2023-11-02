use std::collections::BTreeSet;

use bitcoin_hashes_12::sha256;
use fedimint_core::block::consensus_hash_sha256;
use fedimint_core::encoding::Encodable;
use fedimint_core::epoch::ConsensusItem;

use crate::LOG_CONSENSUS;

// This limits the RAM consumption of a Unit to roughly 10kB
const BYTE_LIMIT: usize = 10_000;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, parity_scale_codec::Encode, parity_scale_codec::Decode,
)]
pub struct UnitData(pub Vec<u8>);

impl UnitData {
    // in order to bound the RAM consumption of a session we have to bound an
    // individual units size, hence the size of its attached unit data in memory
    pub fn is_valid(&self) -> bool {
        self.0.len() <= BYTE_LIMIT
    }
}

pub struct DataProvider {
    mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
    submitted_items: BTreeSet<sha256::Hash>,
    leftover_item: Option<ConsensusItem>,
}

impl DataProvider {
    pub fn new(mempool_item_receiver: async_channel::Receiver<ConsensusItem>) -> Self {
        Self {
            mempool_item_receiver,
            submitted_items: BTreeSet::new(),
            leftover_item: None,
        }
    }
}

#[async_trait::async_trait]
impl aleph_bft::DataProvider<UnitData> for DataProvider {
    async fn get_data(&mut self) -> Option<UnitData> {
        // the length of a vector is encoded in at most 9 bytes
        let mut n_bytes = 9;
        let mut items = Vec::new();

        if let Some(item) = self.leftover_item.take() {
            let n_bytes_item = item
                .consensus_encode_to_vec()
                .expect("Writing to a vector cant fail")
                .len();

            if n_bytes_item + n_bytes <= BYTE_LIMIT {
                n_bytes += n_bytes_item;
                items.push(item);
            } else {
                tracing::warn!(target: LOG_CONSENSUS,"Consensus item length is over BYTE_LIMIT");
            }
        }

        // if the channel is empty we want to return the batch immediately in order to
        // not delay the creation of our next unit, even if the batch is empty
        while let Ok(item) = self.mempool_item_receiver.try_recv() {
            if !self.submitted_items.insert(consensus_hash_sha256(&item)) {
                continue;
            }

            let n_bytes_item = item
                .consensus_encode_to_vec()
                .expect("Writing to a vector cant fail")
                .len();

            if n_bytes + n_bytes_item <= BYTE_LIMIT {
                n_bytes += n_bytes_item;
                items.push(item);
            } else {
                self.leftover_item = Some(item);
                break;
            }
        }

        let bytes = items
            .consensus_encode_to_vec()
            .expect("Writing to a vector cant fail");

        assert!(bytes.len() <= BYTE_LIMIT);

        return Some(UnitData(bytes));
    }
}
