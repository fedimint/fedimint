//! Uses immutable data structures and saves to redb on commit.

use std::fmt::Debug;
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, Mutex};

use fedimint_core::db::{
    DatabaseError, DatabaseResult, IDatabaseTransactionOps, IDatabaseTransactionOpsCore,
    IRawDatabase, IRawDatabaseTransaction, PrefixStream,
};
use fedimint_core::{apply, async_trait_maybe_send};
use futures::stream;
use imbl::OrdMap;
use redb::{Database, ReadableTable, TableDefinition};

const KV_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("fedimint_kv");

#[derive(Debug, Default)]
pub struct DatabaseInsertOperation {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub old_value: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct DatabaseDeleteOperation {
    pub key: Vec<u8>,
    pub old_value: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum DatabaseOperation {
    Insert(DatabaseInsertOperation),
    Delete(DatabaseDeleteOperation),
}

#[derive(Clone)]
pub struct MemAndRedb {
    data: Arc<Mutex<OrdMap<Vec<u8>, Vec<u8>>>>,
    db: Arc<Database>,
}

impl Debug for MemAndRedb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemDatabase").finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct MemAndRedbTransaction<'a> {
    operations: Vec<DatabaseOperation>,
    tx_data: OrdMap<Vec<u8>, Vec<u8>>,
    db: &'a MemAndRedb,
}

#[cfg(not(target_family = "wasm"))]
mod native;

#[cfg(target_family = "wasm")]
mod wasm;

impl MemAndRedb {
    fn new_from_redb(db: Database) -> DatabaseResult<Self> {
        let db = Arc::new(db);
        let mut data = OrdMap::new();

        // Load existing data from redb
        let read_txn = db.begin_read().map_err(DatabaseError::backend)?;
        if let Ok(table) = read_txn.open_table(KV_TABLE) {
            for entry in table.iter().map_err(DatabaseError::backend)? {
                let (key, value) = entry.map_err(DatabaseError::backend)?;
                data.insert(key.value().to_vec(), value.value().to_vec());
            }
        }
        // Table might not exist on first run, which is fine

        Ok(Self {
            data: Arc::new(Mutex::new(data)),
            db,
        })
    }
}

#[apply(async_trait_maybe_send!)]
impl IRawDatabase for MemAndRedb {
    type Transaction<'a> = MemAndRedbTransaction<'a>;

    async fn begin_transaction<'a>(&'a self) -> MemAndRedbTransaction<'a> {
        MemAndRedbTransaction {
            operations: Vec::new(),
            tx_data: {
                let data_lock = self.data.lock().expect("poison");
                data_lock.clone()
            },
            db: self,
        }
    }

    fn checkpoint(&self, _: &Path) -> DatabaseResult<()> {
        unimplemented!()
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a> IDatabaseTransactionOpsCore for MemAndRedbTransaction<'a> {
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>> {
        let val = IDatabaseTransactionOpsCore::raw_get_bytes(self, key).await;
        // Insert data from copy so we can read our own writes
        let old_value = self.tx_data.insert(key.to_vec(), value.to_vec());
        self.operations
            .push(DatabaseOperation::Insert(DatabaseInsertOperation {
                key: key.to_vec(),
                value: value.to_vec(),
                old_value,
            }));
        val
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        Ok(self.tx_data.get(key).cloned())
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        // Remove data from copy so we can read our own writes
        let old_value = self.tx_data.remove(&key.to_vec());
        self.operations
            .push(DatabaseOperation::Delete(DatabaseDeleteOperation {
                key: key.to_vec(),
                old_value: old_value.clone(),
            }));
        Ok(old_value)
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>> {
        let data = self
            .tx_data
            .range::<_, Vec<u8>>(Range {
                start: range.start.to_vec(),
                end: range.end.to_vec(),
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();

        Ok(Box::pin(stream::iter(data)))
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        let data = self
            .tx_data
            .range::<_, Vec<u8>>((key_prefix.to_vec())..)
            .take_while(|(key, _)| key.starts_with(key_prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();

        Ok(Box::pin(stream::iter(data)))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<()> {
        let keys = self
            .tx_data
            .range::<_, Vec<u8>>((key_prefix.to_vec())..)
            .take_while(|(key, _)| key.starts_with(key_prefix))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in keys.iter() {
            let old_value = self.tx_data.remove(&key.to_vec());
            self.operations
                .push(DatabaseOperation::Delete(DatabaseDeleteOperation {
                    key: key.to_vec(),
                    old_value,
                }));
        }
        Ok(())
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        let mut data = self
            .tx_data
            .range::<_, Vec<u8>>((key_prefix.to_vec())..)
            .take_while(|(key, _)| key.starts_with(key_prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        data.sort_by(|a, b| a.cmp(b).reverse());

        Ok(Box::pin(stream::iter(data)))
    }
}

impl<'a> IDatabaseTransactionOps for MemAndRedbTransaction<'a> {}

// In-memory database transaction should only be used for test code and never
// for production as it doesn't properly implement MVCC
#[apply(async_trait_maybe_send!)]
impl<'a> IRawDatabaseTransaction for MemAndRedbTransaction<'a> {
    async fn commit_tx(self) -> DatabaseResult<()> {
        let mut data_locked = self.db.data.lock().expect("poison");
        let write_txn = self.db.db.begin_write().map_err(DatabaseError::backend)?;
        let operations = self.operations;
        let mut data_new = data_locked.clone();
        {
            let mut table = write_txn
                .open_table(KV_TABLE)
                .map_err(DatabaseError::backend)?;

            // Apply all operations
            for op in operations {
                match op {
                    DatabaseOperation::Insert(insert_op) => {
                        table
                            .insert(&insert_op.key[..], &insert_op.value[..])
                            .map_err(DatabaseError::backend)?;
                        let old_value = data_new.insert(insert_op.key, insert_op.value);
                        if old_value != insert_op.old_value {
                            return Err(DatabaseError::WriteConflict);
                        }
                    }
                    DatabaseOperation::Delete(delete_op) => {
                        table
                            .remove(&delete_op.key[..])
                            .map_err(DatabaseError::backend)?;
                        let old_value = data_new.remove(&delete_op.key);
                        if old_value != delete_op.old_value {
                            return Err(DatabaseError::WriteConflict);
                        }
                    }
                }
            }
        }
        // Commit redb transaction
        write_txn.commit().map_err(DatabaseError::backend)?;

        // Update in-memory data
        *data_locked = data_new;
        Ok(())
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use fedimint_core::db::Database;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use tempfile::TempDir;

    use super::*;

    async fn open_temp_db(temp_path: &str) -> (Database, TempDir) {
        let temp_dir = tempfile::Builder::new()
            .prefix(temp_path)
            .tempdir()
            .unwrap();

        let db_path = temp_dir.path().join("test.redb");
        let locked_db = MemAndRedb::new(&db_path).await.unwrap();

        let database = Database::new(locked_db, ModuleDecoderRegistry::default());
        (database, temp_dir)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_insert_elements() {
        let (db, _dir) = open_temp_db("fcb-redb-test-insert-elements").await;
        fedimint_core::db::verify_insert_elements(db).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_remove_nonexisting() {
        let (db, _dir) = open_temp_db("fcb-redb-test-remove-nonexisting").await;
        fedimint_core::db::verify_remove_nonexisting(db).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_remove_existing() {
        let (db, _dir) = open_temp_db("fcb-redb-test-remove-existing").await;
        fedimint_core::db::verify_remove_existing(db).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_read_own_writes() {
        let (db, _dir) = open_temp_db("fcb-redb-test-read-own-writes").await;
        fedimint_core::db::verify_read_own_writes(db).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_prevent_dirty_reads() {
        let (db, _dir) = open_temp_db("fcb-redb-test-prevent-dirty-reads").await;
        fedimint_core::db::verify_prevent_dirty_reads(db).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_find_by_range() {
        let (db, _dir) = open_temp_db("fcb-redb-test-find-by-range").await;
        fedimint_core::db::verify_find_by_range(db).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_find_by_prefix() {
        let (db, _dir) = open_temp_db("fcb-redb-test-find-by-prefix").await;
        fedimint_core::db::verify_find_by_prefix(db).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_commit() {
        let (db, _dir) = open_temp_db("fcb-redb-test-commit").await;
        fedimint_core::db::verify_commit(db).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_prevent_nonrepeatable_reads() {
        let (db, _dir) = open_temp_db("fcb-redb-test-prevent-nonrepeatable-reads").await;
        fedimint_core::db::verify_prevent_nonrepeatable_reads(db).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_phantom_entry() {
        let (db, _dir) = open_temp_db("fcb-redb-test-phantom-entry").await;
        fedimint_core::db::verify_phantom_entry(db).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_write_conflict() {
        let (db, _dir) = open_temp_db("fcb-redb-test-write-conflict").await;
        fedimint_core::db::verify_snapshot_isolation(db).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_remove_by_prefix() {
        let (db, _dir) = open_temp_db("fcb-redb-test-remove-by-prefix").await;
        fedimint_core::db::verify_remove_by_prefix(db).await;
    }
}
