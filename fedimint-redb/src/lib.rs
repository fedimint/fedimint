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
use futures::stream;
use redb::{ReadableTable, TableDefinition};
use tracing::warn;

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
    pub fn open(path: impl AsRef<Path>) -> DatabaseResult<Self> {
        let db = redb::Database::create(path).map_err(|e| DatabaseError::backend(e))?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Opens a redb database from an existing redb Database instance.
    pub fn from_database(db: redb::Database) -> Self {
        Self { db: Arc::new(db) }
    }
}

/// A read-only redb transaction.
pub struct RedbReadTransaction {
    tx: redb::ReadTransaction,
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
        let tx = self
            .db
            .begin_write()
            .expect("Failed to begin write transaction");
        RedbWriteTransaction { tx }
    }

    async fn begin_read_transaction<'a>(&'a self) -> Self::ReadTransaction<'a> {
        let tx = self
            .db
            .begin_read()
            .expect("Failed to begin read transaction");
        RedbReadTransaction { tx }
    }

    fn checkpoint(&self, backup_path: &Path) -> DatabaseResult<()> {
        warn!(
            path = ?backup_path,
            "redb checkpoint is not fully implemented"
        );
        // redb compact() requires &mut self, which we cannot provide through Arc.
        // For now, checkpoint is a no-op. A proper implementation would need
        // to either store the db differently or use a different approach.
        Ok(())
    }
}

// Read transaction implementations

impl IRawDatabaseReadTransaction for RedbReadTransaction {}

#[async_trait]
impl IDatabaseTransactionOpsCore for RedbReadTransaction {
    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        let table = match self.tx.open_table(TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DatabaseError::backend(e)),
        };
        match table.get(key) {
            Ok(Some(value)) => Ok(Some(value.value().to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(DatabaseError::backend(e)),
        }
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        let table = match self.tx.open_table(TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(Box::pin(stream::empty()));
            }
            Err(e) => return Err(DatabaseError::backend(e)),
        };

        let mut results = Vec::new();
        let range = table
            .range::<&[u8]>(key_prefix..)
            .map_err(|e| DatabaseError::backend(e))?;

        for entry in range {
            let (key, value) = entry.map_err(|e| DatabaseError::backend(e))?;
            let key = key.value().to_vec();
            if !key.starts_with(key_prefix) {
                break;
            }
            results.push((key, value.value().to_vec()));
        }

        Ok(Box::pin(stream::iter(results)))
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        let table = match self.tx.open_table(TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(Box::pin(stream::empty()));
            }
            Err(e) => return Err(DatabaseError::backend(e)),
        };

        let mut results = Vec::new();

        // Calculate the end of the prefix range
        let mut prefix_end = key_prefix.to_vec();
        let mut found_end = false;
        for byte in prefix_end.iter_mut().rev() {
            if *byte < 255 {
                *byte += 1;
                found_end = true;
                break;
            }
            *byte = 0;
        }

        let range = if found_end {
            table
                .range::<&[u8]>(key_prefix..prefix_end.as_slice())
                .map_err(|e| DatabaseError::backend(e))?
        } else {
            table
                .range::<&[u8]>(key_prefix..)
                .map_err(|e| DatabaseError::backend(e))?
        };

        for entry in range {
            let (key, value) = entry.map_err(|e| DatabaseError::backend(e))?;
            let key = key.value().to_vec();
            if !key.starts_with(key_prefix) {
                break;
            }
            results.push((key, value.value().to_vec()));
        }

        results.reverse();
        Ok(Box::pin(stream::iter(results)))
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>> {
        let table = match self.tx.open_table(TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(Box::pin(stream::empty()));
            }
            Err(e) => return Err(DatabaseError::backend(e)),
        };

        let mut results = Vec::new();
        let db_range = table
            .range::<&[u8]>(range)
            .map_err(|e| DatabaseError::backend(e))?;

        for entry in db_range {
            let (key, value) = entry.map_err(|e| DatabaseError::backend(e))?;
            results.push((key.value().to_vec(), value.value().to_vec()));
        }

        Ok(Box::pin(stream::iter(results)))
    }
}

// Write transaction implementations

#[async_trait]
impl IDatabaseTransactionOpsCore for RedbWriteTransaction {
    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        let table = match self.tx.open_table(TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DatabaseError::backend(e)),
        };
        let result = match table.get(key) {
            Ok(Some(value)) => Ok(Some(value.value().to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(DatabaseError::backend(e)),
        };
        drop(table);
        result
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        let table = match self.tx.open_table(TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(Box::pin(stream::empty()));
            }
            Err(e) => return Err(DatabaseError::backend(e)),
        };

        let mut results = Vec::new();
        let range = table
            .range::<&[u8]>(key_prefix..)
            .map_err(|e| DatabaseError::backend(e))?;

        for entry in range {
            let (key, value) = entry.map_err(|e| DatabaseError::backend(e))?;
            let key = key.value().to_vec();
            if !key.starts_with(key_prefix) {
                break;
            }
            results.push((key, value.value().to_vec()));
        }

        Ok(Box::pin(stream::iter(results)))
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        let table = match self.tx.open_table(TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(Box::pin(stream::empty()));
            }
            Err(e) => return Err(DatabaseError::backend(e)),
        };

        let mut results = Vec::new();

        // Calculate the end of the prefix range
        let mut prefix_end = key_prefix.to_vec();
        let mut found_end = false;
        for byte in prefix_end.iter_mut().rev() {
            if *byte < 255 {
                *byte += 1;
                found_end = true;
                break;
            }
            *byte = 0;
        }

        let range = if found_end {
            table
                .range::<&[u8]>(key_prefix..prefix_end.as_slice())
                .map_err(|e| DatabaseError::backend(e))?
        } else {
            table
                .range::<&[u8]>(key_prefix..)
                .map_err(|e| DatabaseError::backend(e))?
        };

        for entry in range {
            let (key, value) = entry.map_err(|e| DatabaseError::backend(e))?;
            let key = key.value().to_vec();
            if !key.starts_with(key_prefix) {
                break;
            }
            results.push((key, value.value().to_vec()));
        }

        results.reverse();
        Ok(Box::pin(stream::iter(results)))
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>> {
        let table = match self.tx.open_table(TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(Box::pin(stream::empty()));
            }
            Err(e) => return Err(DatabaseError::backend(e)),
        };

        let mut results = Vec::new();
        let db_range = table
            .range::<&[u8]>(range)
            .map_err(|e| DatabaseError::backend(e))?;

        for entry in db_range {
            let (key, value) = entry.map_err(|e| DatabaseError::backend(e))?;
            results.push((key.value().to_vec(), value.value().to_vec()));
        }

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
        let mut table = self
            .tx
            .open_table(TABLE)
            .map_err(|e| DatabaseError::backend(e))?;
        let old_value = table
            .insert(key, value)
            .map_err(|e| DatabaseError::backend(e))?
            .map(|v| v.value().to_vec());
        Ok(old_value)
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        let mut table = match self.tx.open_table(TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DatabaseError::backend(e)),
        };
        let old_value = table
            .remove(key)
            .map_err(|e| DatabaseError::backend(e))?
            .map(|v| v.value().to_vec());
        Ok(old_value)
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<()> {
        let mut table = match self.tx.open_table(TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
            Err(e) => return Err(DatabaseError::backend(e)),
        };

        // Collect keys to remove first to avoid borrowing issues
        let keys_to_remove: Vec<Vec<u8>> = {
            let range = table
                .range::<&[u8]>(key_prefix..)
                .map_err(|e| DatabaseError::backend(e))?;
            let mut keys = Vec::new();
            for entry in range {
                let (key, _) = entry.map_err(|e| DatabaseError::backend(e))?;
                let key = key.value().to_vec();
                if !key.starts_with(key_prefix) {
                    break;
                }
                keys.push(key);
            }
            keys
        };

        for key in keys_to_remove {
            table
                .remove(key.as_slice())
                .map_err(|e| DatabaseError::backend(e))?;
        }

        Ok(())
    }
}

impl IDatabaseTransactionOps for RedbWriteTransaction {}

#[async_trait]
impl IRawDatabaseTransaction for RedbWriteTransaction {
    async fn commit_tx(self) -> DatabaseResult<()> {
        self.tx.commit().map_err(|e| DatabaseError::backend(e))
    }
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
        let mut tx = db.begin_transaction().await;
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
        let mut tx = db.begin_transaction().await;
        tx.insert_entry(&TestKey(1), &TestValue("hello".to_string()))
            .await;
        tx.commit_tx().await;

        // Remove and commit
        let mut tx = db.begin_transaction().await;
        let old = tx.remove_entry(&TestKey(1)).await;
        assert_eq!(old, Some(TestValue("hello".to_string())));
        tx.commit_tx().await;

        // Verify removed
        let mut tx = db.begin_read_transaction().await;
        assert_eq!(tx.get_value(&TestKey(1)).await, None);
    }
}
