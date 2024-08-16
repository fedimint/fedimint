use std::collections::BTreeSet;
use std::time::Instant;

use fedimint_core::config::ALEPH_BFT_UNIT_BYTE_LIMIT;
use fedimint_core::encoding::Encodable;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::session_outcome::SchnorrSignature;
use fedimint_core::TransactionId;
use tokio::sync::watch;

use crate::LOG_CONSENSUS;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, parity_scale_codec::Encode, parity_scale_codec::Decode,
)]
pub enum UnitData {
    Batch(Vec<u8>),
    Signature(SchnorrSignature),
}

impl UnitData {
    // in order to bound the RAM consumption of a session we have to bound an
    // individual units size, hence the size of its attached unit data in memory
    pub fn is_valid(&self) -> bool {
        match self {
            UnitData::Signature(..) => true,
            UnitData::Batch(bytes, ..) => bytes.len() <= ALEPH_BFT_UNIT_BYTE_LIMIT,
        }
    }
}

pub struct DataProvider {
    mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
    signature_receiver: watch::Receiver<Option<SchnorrSignature>>,
    submitted_transactions: BTreeSet<TransactionId>,
    leftover_item: Option<ConsensusItem>,
    // Since it's possible that `fedimintd` after restart will receive citems it
    // sent before restart, we use the item's length in bytes, as a simple method
    // to self-synchronize. See <https://github.com/fedimint/fedimint/pull/5432#issuecomment-2176860609>
    // for discussion about it.
    timestamp_sender: async_channel::Sender<(Instant, usize)>,
}

impl DataProvider {
    pub fn new(
        mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
        signature_receiver: watch::Receiver<Option<SchnorrSignature>>,
        timestamp_sender: async_channel::Sender<(Instant, usize)>,
    ) -> Self {
        Self {
            mempool_item_receiver,
            signature_receiver,
            submitted_transactions: BTreeSet::new(),
            leftover_item: None,
            timestamp_sender,
        }
    }
}

#[async_trait::async_trait]
impl aleph_bft::DataProvider<UnitData> for DataProvider {
    async fn get_data(&mut self) -> Option<UnitData> {
        // we only attach our signature as no more items can be ordered in this session
        if let Some(signature) = self.signature_receiver.borrow().clone() {
            return Some(UnitData::Signature(signature));
        }

        // the length of a vector is encoded in at most 9 bytes
        let mut n_bytes = 9;
        let mut items = Vec::new();

        if let Some(item) = self.leftover_item.take() {
            let n_bytes_item = item.consensus_encode_to_vec().len();

            if n_bytes_item + n_bytes <= ALEPH_BFT_UNIT_BYTE_LIMIT {
                n_bytes += n_bytes_item;
                items.push(item);
            } else {
                tracing::warn!(target: LOG_CONSENSUS, ?item, "Consensus item length is over BYTE_LIMIT");
            }
        }

        // if the channel is empty we want to return the batch immediately in order to
        // not delay the creation of our next unit, even if the batch is empty
        while let Ok(item) = self.mempool_item_receiver.try_recv() {
            if let ConsensusItem::Transaction(transaction) = &item {
                if !self.submitted_transactions.insert(transaction.tx_hash()) {
                    continue;
                }
            }

            let n_bytes_item = item.consensus_encode_to_vec().len();

            if n_bytes + n_bytes_item <= ALEPH_BFT_UNIT_BYTE_LIMIT {
                n_bytes += n_bytes_item;
                items.push(item);
            } else {
                self.leftover_item = Some(item);
                break;
            }
        }

        if items.is_empty() {
            return None;
        }

        let bytes = items.consensus_encode_to_vec();

        assert!(bytes.len() <= ALEPH_BFT_UNIT_BYTE_LIMIT);

        self.timestamp_sender
            .send((Instant::now(), bytes.len()))
            .await
            .ok();

        Some(UnitData::Batch(bytes))
    }
}
