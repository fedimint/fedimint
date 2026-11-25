use async_trait::async_trait;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use futures::StreamExt as _;
use tracing::info;

use crate::LOG_CONSENSUS;
use crate::consensus::db::{AlephUnitsKey, AlephUnitsPrefix};

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

        let units = dbtx
            .find_by_prefix(&AlephUnitsPrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<Vec<u8>>>()
            .await;

        if !units.is_empty() {
            info!(target: LOG_CONSENSUS, units_len = %units.len(), "Recovering from an in-session-shutdown");
        }

        Ok(units.into_iter().flatten().collect())
    }
}

/// Writes the AlephBFT backup with one synced database transaction per unit
/// of ours instead of one per unit.
///
/// AlephBFT only needs our own units to be durable before `append` returns,
/// since it broadcasts them right after. The units of other peers are held in
/// memory until then and written in the same transaction, which persists them
/// before the unit of ours that may reference them. A crash therefore loses at
/// most units of other peers newer than our last unit, which leaves the backup
/// consistent and which we fetch from our peers again.
pub struct BackupWriter {
    db: Database,
    units_index: u64,
    buffer: Vec<Vec<u8>>,
}

impl BackupWriter {
    pub async fn new(db: Database) -> Self {
        let units_index = db
            .begin_transaction_nc()
            .await
            .find_by_prefix_sorted_descending(&AlephUnitsPrefix)
            .await
            .next()
            .await
            .map_or(0, |entry| (entry.0.0) + 1);

        Self {
            db,
            units_index,
            buffer: Vec::new(),
        }
    }
}

#[async_trait]
impl aleph_bft::BackupWriter for BackupWriter {
    async fn append(&mut self, data: &[u8], flush: bool) -> std::io::Result<()> {
        self.buffer.push(data.to_owned());

        if !flush {
            return Ok(());
        }

        let mut dbtx = self.db.begin_transaction().await;

        for unit in self.buffer.drain(..) {
            dbtx.insert_new_entry(&AlephUnitsKey(self.units_index), &unit)
                .await;

            self.units_index += 1;
        }

        dbtx.commit_tx_result()
            .await
            .expect("This is the only place where we write to this key");

        Ok(())
    }
}

#[cfg(test)]
mod tests;
