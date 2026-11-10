use std::collections::BTreeSet;

use async_trait::async_trait;
use bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use futures::StreamExt as _;
use tracing::info;

use crate::LOG_CONSENSUS;
use crate::consensus::db::{AlephUnitsKey, AlephUnitsPrefix};

/// Identifies a unit in the backup by its encoding.
///
/// AlephBFT passes every unit it adds to its DAG to the [`BackupWriter`],
/// including the units it has just replayed from this backup. Storing those
/// again appends a full copy of the session's units on every restart within a
/// session, and a guardian that keeps restarting in a stalled session then
/// loads every copy at once at its next start. The backup therefore holds each
/// unit once: the writer skips units it already stored, and the reader skips
/// copies written before this rule existed.
fn unit_digest(unit: &[u8]) -> sha256::Hash {
    sha256::Hash::hash(unit)
}

pub struct BackupReader {
    db: Database,
}

impl BackupReader {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}

#[async_trait]
impl aleph_bft::BackupReader for BackupReader {
    async fn read(&mut self) -> std::io::Result<Vec<u8>> {
        let mut dbtx = self.db.begin_transaction_nc().await;

        let mut stored = 0_usize;
        let mut loaded = BTreeSet::new();
        let mut backup = Vec::new();

        let mut units = dbtx.find_by_prefix(&AlephUnitsPrefix).await;
        while let Some((_, unit)) = units.next().await {
            stored += 1;

            // Keep the first copy: it precedes every unit stored after it, so
            // the units still appear after their parents.
            if loaded.insert(unit_digest(&unit)) {
                backup.extend_from_slice(&unit);
            }
        }

        if stored != 0 {
            info!(
                target: LOG_CONSENSUS,
                units_len = %stored,
                unique_units_len = %loaded.len(),
                "Recovering from an in-session-shutdown"
            );
        }

        Ok(backup)
    }
}

pub struct BackupWriter {
    db: Database,
    units_index: u64,
    stored: BTreeSet<sha256::Hash>,
}

impl BackupWriter {
    pub async fn new(db: Database) -> Self {
        let mut units_index = 0;
        let mut stored = BTreeSet::new();

        {
            let mut dbtx = db.begin_transaction_nc().await;
            let mut units = dbtx.find_by_prefix(&AlephUnitsPrefix).await;
            while let Some((key, unit)) = units.next().await {
                units_index = units_index.max(key.0 + 1);
                stored.insert(unit_digest(&unit));
            }
        }

        Self {
            db,
            units_index,
            stored,
        }
    }
}

#[async_trait]
impl aleph_bft::BackupWriter for BackupWriter {
    async fn append(&mut self, data: &[u8]) -> std::io::Result<()> {
        if !self.stored.insert(unit_digest(data)) {
            return Ok(());
        }

        let mut dbtx = self.db.begin_transaction().await;

        dbtx.insert_new_entry(&AlephUnitsKey(self.units_index), &data.to_owned())
            .await;

        self.units_index += 1;

        dbtx.commit_tx_result()
            .await
            .expect("This is the only place where we write to this key");

        Ok(())
    }
}

#[cfg(test)]
mod tests;
