use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use bitcoin_hashes::{sha256, Hash};
use fedimint_core::core::{DynModuleConsensusItem, ModuleInstanceId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::TransactionId;
use fedimint_logging::LOG_CONSENSUS;
use futures::StreamExt;
use tracing::info;

use super::db::{ConsensusChecksumKey, ConsensusChecksumPrefix};

/// Simple helper object that tracks determinism of consensus item processing
///
/// Note that the implementation does not support any form of a rollback,
/// and thus all `track_` methods must be called after last faliable step
/// of consensus item processing.
#[derive(Debug, Clone)]
pub struct ConsensusChecksumTracker {
    /// Currently
    hashes: BTreeMap<ConsensusChecksumKey, [u8; 32]>,
}

impl ConsensusChecksumTracker {
    /// Create [`Self`] by loading all checksum from the database
    pub async fn new(dbtx: &mut DatabaseTransaction<'_>) -> Self {
        Self {
            hashes: dbtx
                .find_by_prefix(&ConsensusChecksumPrefix)
                .await
                .collect()
                .await,
        }
    }

    /// Generalized logic calculating consensus checksum for a given key
    /// and writing it back to database.
    async fn track<F>(
        &mut self,
        dbtx: &mut DatabaseTransaction<'_>,
        key: ConsensusChecksumKey,
        write_bytes: F,
    ) where
        F: FnOnce(&mut sha256::HashEngine),
    {
        let mut engine = sha256::HashEngine::default();
        let hash = self.hashes.entry(key).or_default();

        engine.write_all(hash.as_ref()).expect("can't fail");

        write_bytes(&mut engine);

        *hash = *sha256::Hash::from_engine(engine).as_byte_array();
        dbtx.insert_entry(&key, hash).await;
    }

    /// Account for processing a module consensus item
    pub async fn track_module_citem(
        &mut self,
        dbtx: &mut DatabaseTransaction<'_>,
        module_id: ModuleInstanceId,
        module_item: &DynModuleConsensusItem,
    ) {
        self.track(dbtx, ConsensusChecksumKey::CItem(module_id), |w| {
            module_item.consensus_encode(w).expect("can't fail");
        })
        .await;
    }

    /// Account for processing a consensus transaction
    pub async fn track_tx(
        &mut self,
        dbtx: &mut DatabaseTransaction<'_>,
        txid: &TransactionId,
        input_module_id: &BTreeSet<ModuleInstanceId>,
        output_module_id: &BTreeSet<ModuleInstanceId>,
    ) {
        for module_id in input_module_id {
            self.track(dbtx, ConsensusChecksumKey::TxInput(*module_id), |w| {
                w.write_all(txid.as_ref()).expect("can't fail");
            })
            .await;
        }
        for module_id in output_module_id {
            self.track(dbtx, ConsensusChecksumKey::TxOutput(*module_id), |w| {
                w.write_all(txid.as_ref()).expect("can't fail");
            })
            .await;
        }
    }

    /// Report (log) current checksum(s)
    pub fn report(&self, session_idx: u64) {
        let mut sum = [0u8; 32];

        for (key, checksum) in &self.hashes {
            info!(target: LOG_CONSENSUS, k = ?key, v = hex::encode(checksum), session_idx, "Consensus checksum");

            for (i, &b) in checksum.iter().enumerate() {
                sum[i] ^= b;
            }
        }
        info!(target: LOG_CONSENSUS, k = "Summary", v = hex::encode(sum), session_idx, "Consensus checksum");
    }
}
