#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]

use std::fmt;
use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result};
use async_trait::async_trait;
use fedimint_core::db::{
    IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase, IRawDatabaseTransaction,
    PrefixStream,
};
use fedimint_core::task::block_in_place;
use fjall::{
    Config, TransactionalKeyspace, TransactionalPartitionHandle, WriteTransaction as FjallWriteTx,
};
use futures::stream;
use tracing::debug;

/// Fjall database wrapper for Fedimint
pub struct FjallDb {
    keyspace: TransactionalKeyspace,
    partition: TransactionalPartitionHandle,
}

/// Fjall transaction wrapper for Fedimint
pub struct FjallDbTransaction<'a> {
    db: &'a FjallDb,
    tx: FjallWriteTx,
}

impl FjallDb {
    /// Opens a new Fjall database at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        block_in_place(|| Self::open_blocking(path))
    }

    /// Opens a new Fjall database at the given path (blocking)
    pub fn open_blocking(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        debug!("Opening fjall database at: {:?}", path);

        let keyspace = Config::new(path)
            .open_transactional()
            .context("Failed to open fjall transactional keyspace")?;

        // Create a single partition for all data
        let partition = keyspace
            .open_partition("default", fjall::PartitionCreateOptions::default())
            .context("Failed to open default partition")?;

        Ok(Self {
            keyspace,
            partition,
        })
    }
}

impl fmt::Debug for FjallDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FjallDb").finish()
    }
}

impl fmt::Debug for FjallDbTransaction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FjallDbTransaction").finish()
    }
}

#[async_trait]
impl IRawDatabase for FjallDb {
    type Transaction<'a> = FjallDbTransaction<'a>;

    async fn begin_transaction<'a>(&'a self) -> Self::Transaction<'a> {
        let tx = block_in_place(|| {
            self.keyspace
                .write_tx()
                .expect("Failed to begin fjall transaction")
        });

        FjallDbTransaction { db: self, tx }
    }

    fn checkpoint(&self, _backup_path: &Path) -> Result<()> {
        unimplemented!("Checkpoint not implemented for fjall backend")
    }
}

#[async_trait]
impl IDatabaseTransactionOpsCore for FjallDbTransaction<'_> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        block_in_place(|| {
            // Get old value first
            let old_value = self.tx.get(&self.db.partition, key)?.map(|v| v.to_vec());

            // Insert new value
            self.tx.insert(&self.db.partition, key, value);

            Ok(old_value)
        })
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        block_in_place(|| Ok(self.tx.get(&self.db.partition, key)?.map(|v| v.to_vec())))
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        block_in_place(|| {
            // Get old value first
            let old_value = self.tx.get(&self.db.partition, key)?.map(|v| v.to_vec());

            // Remove the key
            self.tx.remove(&self.db.partition, key);

            Ok(old_value)
        })
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        let prefix = key_prefix.to_vec();

        block_in_place(|| {
            // Collect results to avoid Send issues for stream.
            let results: Vec<(Vec<u8>, Vec<u8>)> = self
                .tx
                .prefix(&self.db.partition, &prefix)
                .map(|kv| {
                    let kv = kv.expect("Failed to read from fjall");
                    (kv.0.to_vec(), kv.1.to_vec())
                })
                .collect();

            Ok(Box::pin(stream::iter(results)) as PrefixStream<'_>)
        })
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        let prefix = key_prefix.to_vec();

        block_in_place(|| {
            // Collect results to avoid Send issues for stream.
            // the iterator is !Send, we can't convert it to stream directly.
            let results: Vec<(Vec<u8>, Vec<u8>)> = self
                .tx
                .prefix(&self.db.partition, &prefix)
                .rev()
                .map(|kv| {
                    let kv = kv.expect("Failed to read from fjall");
                    (kv.0.to_vec(), kv.1.to_vec())
                })
                .collect();

            Ok(Box::pin(stream::iter(results)) as PrefixStream<'_>)
        })
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> Result<PrefixStream<'_>> {
        let start = range.start.to_vec();
        let end = range.end.to_vec();

        block_in_place(|| {
            // Collect results within range
            let results: Vec<(Vec<u8>, Vec<u8>)> = self
                .tx
                .range::<Vec<u8>, _>(&self.db.partition, &start..&end)
                .map(|kv| {
                    let kv = kv.expect("Failed to read from fjall");
                    (kv.0.to_vec(), kv.1.to_vec())
                })
                .collect();

            Ok(Box::pin(stream::iter(results)) as PrefixStream<'_>)
        })
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        let prefix = key_prefix.to_vec();

        block_in_place(|| {
            // Collect keys to remove first to avoid iterator invalidation
            let keys_to_remove: Vec<Vec<u8>> = self
                .tx
                .prefix(&self.db.partition, &prefix)
                .map(|kv| {
                    let kv = kv.expect("Failed to read from fjall");
                    kv.0.to_vec()
                })
                .collect();

            // Remove all collected keys
            for key in keys_to_remove {
                self.tx.remove(&self.db.partition, &key);
            }

            Ok(())
        })
    }
}

#[async_trait]
impl IDatabaseTransactionOps for FjallDbTransaction<'_> {
    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        unimplemented!("Savepoints not implemented for fjall backend")
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        unimplemented!("Savepoints not implemented for fjall backend")
    }
}

#[async_trait]
impl IRawDatabaseTransaction for FjallDbTransaction<'_> {
    async fn commit_tx(self) -> Result<()> {
        block_in_place(|| {
            // Commit the transaction
            self.tx
                .commit()
                .map_err(|e| anyhow::anyhow!("Failed to commit fjall transaction: {:?}", e))?
                .map_err(|conflict| anyhow::anyhow!("Transaction conflict: {:?}", conflict))
        })
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::db::*;
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    use super::*;

    async fn open_temp_db() -> Result<Database> {
        let tmp = tempfile::tempdir()?;
        Ok(FjallDb::open(tmp.path())?.into())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_insert_elements() -> Result<()> {
        let db = open_temp_db().await?;
        verify_insert_elements(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_remove_nonexisting() -> Result<()> {
        let db = open_temp_db().await?;
        verify_remove_nonexisting(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_remove_existing() -> Result<()> {
        let db = open_temp_db().await?;
        verify_remove_existing(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_read_own_writes() -> Result<()> {
        let db = open_temp_db().await?;
        verify_read_own_writes(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_prevent_dirty_reads() -> Result<()> {
        let db = open_temp_db().await?;
        verify_prevent_dirty_reads(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_by_prefix() -> Result<()> {
        let db = open_temp_db().await?;
        verify_find_by_prefix(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_commit() -> Result<()> {
        let db = open_temp_db().await?;
        verify_commit(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_by_range() -> Result<()> {
        let db = open_temp_db().await?;
        verify_find_by_range(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_phantom_entry() -> Result<()> {
        let db = open_temp_db().await?;
        verify_phantom_entry(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_write_conflict() -> Result<()> {
        let db = open_temp_db().await?;
        expect_write_conflict(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_module_dbtx() -> Result<()> {
        let db = open_temp_db().await?;
        verify_module_prefix(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_module_db() -> Result<()> {
        let module_instance_id = 1;
        let tmp_module = tempfile::tempdir()?;
        let module_db = Database::new(
            FjallDb::open(tmp_module.path())?,
            ModuleDecoderRegistry::default(),
        );

        let db = open_temp_db().await?;
        verify_module_db(db, module_db.with_prefix_module_id(module_instance_id).0).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_prevent_nonrepeatable_reads() -> Result<()> {
        let db = open_temp_db().await?;
        verify_prevent_nonrepeatable_reads(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_snapshot_isolation() -> Result<()> {
        let db = open_temp_db().await?;
        verify_snapshot_isolation(db).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_remove_by_prefix() -> Result<()> {
        let db = open_temp_db().await?;
        verify_remove_by_prefix(db).await;
        Ok(())
    }
}
