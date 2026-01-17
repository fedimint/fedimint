//! Direct redb database implementation for Fedimint server.
//!
//! This implementation uses redb's native transaction types directly without
//! buffering writes in memory. It does not support optimistic transactions
//! (`begin_transaction_nc`), which is fine for the server since it now properly
//! uses `begin_read_transaction` for reads and `begin_write_transaction` for
//! writes.

use std::fmt::Debug;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_core::db::{
    DatabaseError, DatabaseResult, IDatabaseTransactionOps, IDatabaseTransactionOpsCore,
    IDatabaseTransactionOpsCoreWrite, IRawDatabase, IRawDatabaseReadTransaction,
    IRawDatabaseTransaction, PrefixStream,
};
use futures::{StreamExt as _, stream};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("fedimint");

/// A redb-backed database for Fedimint server.
#[derive(Clone)]
pub struct RedbDatabase {
    db: Arc<redb::Database>,
}

impl Debug for RedbDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbDatabase").finish_non_exhaustive()
    }
}

impl RedbDatabase {
    /// Opens or creates a redb database at the given path.
    ///
    /// Creates the fedimint table if it doesn't exist.
    pub fn open(path: impl AsRef<Path>) -> DatabaseResult<Self> {
        let db = redb::Database::create(path).map_err(DatabaseError::backend)?;

        // Create the table if it doesn't exist
        let tx = db.begin_write().map_err(DatabaseError::backend)?;
        tx.open_table(TABLE).map_err(DatabaseError::backend)?;
        tx.commit().map_err(DatabaseError::backend)?;

        Ok(Self { db: Arc::new(db) })
    }
}

/// A read-only redb transaction.
///
/// Stores the `ReadOnlyTable` directly because it uses `Arc<TransactionGuard>`
/// internally, allowing iterators to have `'static` lifetime for streaming.
pub struct RedbReadTransaction {
    table: redb::ReadOnlyTable<&'static [u8], &'static [u8]>,
}

impl Debug for RedbReadTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbReadTransaction")
            .finish_non_exhaustive()
    }
}

/// A read-write redb transaction.
pub struct RedbWriteTransaction {
    tx: redb::WriteTransaction,
}

impl Debug for RedbWriteTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbWriteTransaction")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl IRawDatabase for RedbDatabase {
    type Transaction<'a> = RedbWriteTransaction;
    type ReadTransaction<'a> = RedbReadTransaction;

    async fn begin_transaction<'a>(&'a self) -> Self::Transaction<'a> {
        RedbWriteTransaction {
            tx: self
                .db
                .begin_write()
                .expect("Failed to begin write transaction"),
        }
    }

    async fn begin_read_transaction<'a>(&'a self) -> Self::ReadTransaction<'a> {
        let tx = self
            .db
            .begin_read()
            .expect("Failed to begin read transaction");

        let table = tx
            .open_table(TABLE)
            .expect("Failed to open table for read transaction");

        RedbReadTransaction { table }
    }

    fn checkpoint(&self, _backup_path: &Path) -> DatabaseResult<()> {
        Ok(())
    }
}

impl IRawDatabaseReadTransaction for RedbReadTransaction {}

#[async_trait]
impl IDatabaseTransactionOpsCore for RedbReadTransaction {
    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        let entry = self
            .table
            .get(key)
            .map_err(DatabaseError::backend)?
            .map(|value| value.value().to_vec());

        Ok(entry)
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        let prefix = key_prefix.to_vec();

        let iter = self
            .table
            .range::<&[u8]>(key_prefix..)
            .map_err(DatabaseError::backend)?
            .filter_map(|entry| entry.ok())
            .map(|(key, value)| (key.value().to_vec(), value.value().to_vec()))
            .take_while(move |(key, _)| key.starts_with(&prefix));

        Ok(Box::pin(stream::iter(iter)))
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        // For descending order, we need to collect and reverse since redb
        // doesn't support reverse iteration on Range directly
        let prefix = key_prefix.to_vec();

        let mut results: Vec<_> = self
            .table
            .range::<&[u8]>(key_prefix..)
            .map_err(DatabaseError::backend)?
            .filter_map(|entry| entry.ok())
            .map(|(key, value)| (key.value().to_vec(), value.value().to_vec()))
            .take_while(|(key, _)| key.starts_with(&prefix))
            .collect();

        results.reverse();

        Ok(Box::pin(stream::iter(results)))
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>> {
        let db_range = self
            .table
            .range::<&[u8]>(range)
            .map_err(DatabaseError::backend)?
            .filter_map(|entry| entry.ok())
            .map(|(key, value)| (key.value().to_vec(), value.value().to_vec()));

        Ok(Box::pin(stream::iter(db_range)))
    }
}

#[async_trait]
impl IDatabaseTransactionOpsCore for RedbWriteTransaction {
    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        let table = self.tx.open_table(TABLE).map_err(DatabaseError::backend)?;

        let entry = table
            .get(key)
            .map_err(DatabaseError::backend)?
            .map(|value| value.value().to_vec());

        Ok(entry)
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        let prefix = key_prefix.to_vec();

        let results: Vec<_> = self
            .tx
            .open_table(TABLE)
            .map_err(DatabaseError::backend)?
            .range::<&[u8]>(key_prefix..)
            .map_err(DatabaseError::backend)?
            .filter_map(|entry| entry.ok())
            .map(|(key, value)| (key.value().to_vec(), value.value().to_vec()))
            .take_while(|(key, _)| key.starts_with(&prefix))
            .collect();

        Ok(Box::pin(stream::iter(results)))
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        let prefix = key_prefix.to_vec();

        let mut results: Vec<_> = self
            .tx
            .open_table(TABLE)
            .map_err(DatabaseError::backend)?
            .range::<&[u8]>(key_prefix..)
            .map_err(DatabaseError::backend)?
            .filter_map(|entry| entry.ok())
            .map(|(key, value)| (key.value().to_vec(), value.value().to_vec()))
            .take_while(|(key, _)| key.starts_with(&prefix))
            .collect();

        results.reverse();

        Ok(Box::pin(stream::iter(results)))
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>> {
        let results: Vec<_> = self
            .tx
            .open_table(TABLE)
            .map_err(DatabaseError::backend)?
            .range::<&[u8]>(range)
            .map_err(DatabaseError::backend)?
            .filter_map(|entry| entry.ok())
            .map(|(key, value)| (key.value().to_vec(), value.value().to_vec()))
            .collect();

        Ok(Box::pin(stream::iter(results)))
    }
}

#[async_trait]
impl IDatabaseTransactionOpsCoreWrite for RedbWriteTransaction {
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>> {
        let mut table = self.tx.open_table(TABLE).map_err(DatabaseError::backend)?;

        let old_value = table
            .insert(key, value)
            .map_err(DatabaseError::backend)?
            .map(|v| v.value().to_vec());

        Ok(old_value)
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        let mut table = self.tx.open_table(TABLE).map_err(DatabaseError::backend)?;

        let old_value = table
            .remove(key)
            .map_err(DatabaseError::backend)?
            .map(|v| v.value().to_vec());

        Ok(old_value)
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<()> {
        let mut table = self.tx.open_table(TABLE).map_err(DatabaseError::backend)?;

        let prefix = key_prefix.to_vec();

        let keys_to_remove: Vec<_> = table
            .range::<&[u8]>(key_prefix..)
            .map_err(DatabaseError::backend)?
            .filter_map(|entry| entry.ok())
            .map(|(key, _)| key.value().to_vec())
            .take_while(|key| key.starts_with(&prefix))
            .collect();

        for key in keys_to_remove {
            table
                .remove(key.as_slice())
                .map_err(DatabaseError::backend)?;
        }

        Ok(())
    }
}

impl IDatabaseTransactionOps for RedbWriteTransaction {}

#[async_trait]
impl IRawDatabaseTransaction for RedbWriteTransaction {
    async fn commit_tx(self) -> DatabaseResult<()> {
        self.tx.commit().map_err(DatabaseError::backend)
    }
}

/// Migrates all data from one database to another.
///
/// This function copies all key-value pairs from the source database
/// to the destination database. It is useful for migrating from
/// one database backend to another, e.g., RocksDB to redb.
pub async fn migrate_database<S, D>(source: &S, dest: &D) -> DatabaseResult<()>
where
    S: IRawDatabase,
    D: IRawDatabase,
{
    let mut read_tx = source.begin_read_transaction().await;
    let mut write_tx = dest.begin_transaction().await;

    let mut all_entries = read_tx.raw_find_by_prefix(&[]).await?;

    while let Some((key, value)) = all_entries.next().await {
        write_tx.raw_insert_bytes(&key, &value).await?;
    }

    drop(all_entries);
    drop(read_tx);

    write_tx.commit_tx().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use fedimint_core::db::{
        Database, IDatabaseTransactionOpsCoreTyped, IReadDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleRegistry;
    use fedimint_core::{impl_db_lookup, impl_db_record};

    use super::*;

    #[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, PartialOrd, Ord)]
    struct TestKey(u64);

    #[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq)]
    struct TestValue(String);

    #[allow(dead_code)]
    #[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, PartialOrd, Ord)]
    struct TestKeyPrefix;

    impl_db_record!(key = TestKey, value = TestValue, db_prefix = 0x01,);
    impl_db_lookup!(key = TestKey, query_prefix = TestKeyPrefix,);

    fn open_temp_db(name: &str) -> Database {
        let path = tempfile::Builder::new()
            .prefix(name)
            .suffix(".redb")
            .tempfile()
            .unwrap()
            .into_temp_path();

        Database::new(
            RedbDatabase::open(&path).unwrap(),
            ModuleRegistry::default(),
        )
    }

    #[tokio::test]
    async fn test_basic_operations() {
        let db = open_temp_db("test_basic");

        // Write some data
        let mut tx = db.begin_write_transaction().await;
        tx.insert_entry(&TestKey(1), &TestValue("hello".to_string()))
            .await;
        tx.insert_entry(&TestKey(2), &TestValue("world".to_string()))
            .await;
        tx.commit_tx().await;

        // Read it back
        let mut tx = db.begin_read_transaction().await;
        assert_eq!(
            tx.get_value(&TestKey(1)).await,
            Some(TestValue("hello".to_string()))
        );
        assert_eq!(
            tx.get_value(&TestKey(2)).await,
            Some(TestValue("world".to_string()))
        );
        assert_eq!(tx.get_value(&TestKey(3)).await, None);
    }

    #[tokio::test]
    async fn test_remove() {
        let db = open_temp_db("test_remove");

        // Write and commit
        let mut tx = db.begin_write_transaction().await;
        tx.insert_entry(&TestKey(1), &TestValue("hello".to_string()))
            .await;
        tx.commit_tx().await;

        // Remove and commit
        let mut tx = db.begin_write_transaction().await;
        let old = tx.remove_entry(&TestKey(1)).await;
        assert_eq!(old, Some(TestValue("hello".to_string())));
        tx.commit_tx().await;

        // Verify removed
        let mut tx = db.begin_read_transaction().await;
        assert_eq!(tx.get_value(&TestKey(1)).await, None);
    }
}
