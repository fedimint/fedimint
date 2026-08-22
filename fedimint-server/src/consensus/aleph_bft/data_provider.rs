use std::collections::BTreeSet;
use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use fedimint_core::TransactionId;
use fedimint_core::config::ALEPH_BFT_UNIT_BYTE_LIMIT;
use fedimint_core::encoding::Encodable;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::secp256k1::schnorr;
use tokio::sync::watch;

use crate::LOG_CONSENSUS;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, parity_scale_codec::Encode, parity_scale_codec::Decode,
)]
pub enum UnitData {
    Batch(Vec<u8>),
    Signature([u8; 64]),
}

impl UnitData {
    // in order to bound the RAM consumption of a session we have to bound an
    // individual units size, hence the size of its attached unit data in memory
    pub fn is_valid(&self) -> bool {
        match self {
            UnitData::Signature(..) => true,
            UnitData::Batch(bytes) => bytes.len() <= ALEPH_BFT_UNIT_BYTE_LIMIT,
        }
    }
}

/// The number of batches we have attached to our own units which have not been
/// ordered yet, shared between the [`DataProvider`] which creates them and the
/// [`super::finalization_handler::FinalizationHandler`] which observes them
/// being ordered.
#[derive(Clone, Default)]
pub struct UnorderedBatches(Arc<AtomicUsize>);

impl UnorderedBatches {
    pub fn created(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn ordered(&self) {
        // Aleph BFT replays every unit of the current session from our backup on
        // a restart, thereby ordering batches we have not created in this
        // process. Hence we saturate at zero instead of underflowing.
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |batches| {
                Some(batches.saturating_sub(1))
            })
            .expect("The closure always returns Some");
    }

    pub fn is_empty(&self) -> bool {
        self.0.load(Ordering::Relaxed) == 0
    }
}

pub struct DataProvider {
    mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
    signature_receiver: watch::Receiver<Option<schnorr::Signature>>,
    submitted_transactions: BTreeSet<TransactionId>,
    leftover_item: Option<ConsensusItem>,
    timestamp_sender: async_channel::Sender<Instant>,
    is_recovery: bool,
    unordered_batches: UnorderedBatches,
}

impl DataProvider {
    pub fn new(
        mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
        signature_receiver: watch::Receiver<Option<schnorr::Signature>>,
        timestamp_sender: async_channel::Sender<Instant>,
        is_recovery: bool,
        unordered_batches: UnorderedBatches,
    ) -> Self {
        Self {
            mempool_item_receiver,
            signature_receiver,
            submitted_transactions: BTreeSet::new(),
            leftover_item: None,
            timestamp_sender,
            is_recovery,
            unordered_batches,
        }
    }
}

#[async_trait::async_trait]
impl aleph_bft::DataProvider<UnitData> for DataProvider {
    async fn get_data(&mut self) -> Option<UnitData> {
        loop {
            // we only attach our signature as no more items can be ordered in this session
            if let Some(signature) = *self.signature_receiver.borrow() {
                return Some(UnitData::Signature(signature.serialize()));
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

            // we only drain the items which are available right away in order to not
            // delay the creation of our next unit
            while let Ok(item) = self.mempool_item_receiver.try_recv() {
                if let ConsensusItem::Transaction(transaction) = &item
                    && !self.submitted_transactions.insert(transaction.tx_hash())
                {
                    continue;
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

            if !items.is_empty() {
                if !self.is_recovery {
                    self.timestamp_sender.send(Instant::now()).await.ok();
                }

                let bytes = items.consensus_encode_to_vec();

                assert!(bytes.len() <= ALEPH_BFT_UNIT_BYTE_LIMIT);

                self.unordered_batches.created();

                return Some(UnitData::Batch(bytes));
            }

            // We have nothing to order ourselves. As long as a batch of ours still
            // awaits ordering we keep creating units without data such that the
            // broadcast grows the dag and orders it, otherwise there is no work to be
            // done and we go quiescent until an item is submitted to us or the session
            // ends.
            if !self.unordered_batches.is_empty() {
                return None;
            }

            tokio::select! {
                item = self.mempool_item_receiver.recv() => {
                    match item {
                        Ok(item) => self.leftover_item = Some(item),
                        // the sender is dropped as the server shuts down, in which case
                        // we park instead of spinning on the closed channel
                        Err(..) => pending::<()>().await,
                    }
                }
                changed = self.signature_receiver.changed() => {
                    if changed.is_err() {
                        pending::<()>().await;
                    }
                }
            }
        }
    }
}
