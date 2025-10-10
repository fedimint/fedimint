use std::fmt::{self, Debug};
use std::ops::Range;
use std::path::Path;

use anyhow::Result;
use futures::{StreamExt, stream};
use imbl::OrdMap;
use macro_rules_attribute::apply;

use super::{
    IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase, IRawDatabaseTransaction,
};
use crate::async_trait_maybe_send;
use crate::db::PrefixStream;

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

#[derive(Default)]
pub struct MemDatabase {
    data: std::sync::RwLock<OrdMap<Vec<u8>, Vec<u8>>>,
}

impl fmt::Debug for MemDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("MemDatabase {{}}",))
    }
}
pub struct MemTransaction<'a> {
    operations: Vec<DatabaseOperation>,
    tx_data: OrdMap<Vec<u8>, Vec<u8>>,
    db: &'a MemDatabase,
    savepoint: OrdMap<Vec<u8>, Vec<u8>>,
    num_pending_operations: usize,
    num_savepoint_operations: usize,
}

impl fmt::Debug for MemTransaction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "MemTransaction {{ db={:?}, operations_len={}, tx_data_len={}, savepoint_len={}, num_pending_ops={}, num_savepoint_ops={} }}",
            self.db,
            self.operations.len(),
            self.tx_data.len(),
            self.savepoint.len(),
            self.num_pending_operations,
            self.num_savepoint_operations,
        ))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct DummyError;

impl MemDatabase {
    pub fn new() -> Self {
        Self::default()
    }
}

#[apply(async_trait_maybe_send!)]
impl IRawDatabase for MemDatabase {
    type Transaction<'a> = MemTransaction<'a>;
    async fn begin_transaction<'a>(&'a self) -> MemTransaction<'a> {
        let db_copy = self.data.read().expect("Poisoned rwlock").clone();
        let mut memtx = MemTransaction {
            operations: Vec::new(),
            tx_data: db_copy.clone(),
            db: self,
            savepoint: db_copy,
            num_pending_operations: 0,
            num_savepoint_operations: 0,
        };

        memtx.set_tx_savepoint().await.expect("can't fail");
        memtx
    }

    fn checkpoint(&self, _backup_path: &Path) -> Result<()> {
        Ok(())
    }
}

// In-memory database transaction should only be used for test code and never
// for production as it doesn't properly implement MVCC
#[apply(async_trait_maybe_send!)]
impl IDatabaseTransactionOpsCore for MemTransaction<'_> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        // Insert data from copy so we can read our own writes
        let old_value = self.tx_data.insert(key.to_vec(), value.to_owned());
        self.operations
            .push(DatabaseOperation::Insert(DatabaseInsertOperation {
                key: key.to_vec(),
                value: value.to_owned(),
                old_value: old_value.clone(),
            }));
        self.num_pending_operations += 1;
        Ok(old_value)
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.tx_data.get(key).cloned())
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // Remove data from copy so we can read our own writes
        let old_value = self.tx_data.remove(&key.to_vec());
        self.operations
            .push(DatabaseOperation::Delete(DatabaseDeleteOperation {
                key: key.to_vec(),
                old_value: old_value.clone(),
            }));
        self.num_pending_operations += 1;
        Ok(old_value)
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        let keys = self
            .raw_find_by_prefix(key_prefix)
            .await?
            .map(|kv| kv.0)
            .collect::<Vec<_>>()
            .await;
        for key in keys {
            self.raw_remove_entry(key.as_slice()).await?;
        }
        Ok(())
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        let data = self
            .tx_data
            .range((key_prefix.to_vec())..)
            .take_while(|(key, _)| key.starts_with(key_prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        Ok(Box::pin(stream::iter(data)))
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        let mut data = self
            .tx_data
            .range((key_prefix.to_vec())..)
            .take_while(|(key, _)| key.starts_with(key_prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        data.sort_by(|a, b| a.cmp(b).reverse());

        Ok(Box::pin(stream::iter(data)))
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> Result<PrefixStream<'_>> {
        let data = self
            .tx_data
            .range(Range {
                start: range.start.to_vec(),
                end: range.end.to_vec(),
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        Ok(Box::pin(stream::iter(data)))
    }
}

#[apply(async_trait_maybe_send!)]
impl IDatabaseTransactionOps for MemTransaction<'_> {
    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        self.tx_data = self.savepoint.clone();

        // Remove any pending operations beyond the savepoint
        let removed_ops = self.num_pending_operations - self.num_savepoint_operations;
        for _i in 0..removed_ops {
            self.operations.pop();
        }

        Ok(())
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        self.savepoint = self.tx_data.clone();
        self.num_savepoint_operations = self.num_pending_operations;
        Ok(())
    }
}

#[apply(async_trait_maybe_send!)]
impl IRawDatabaseTransaction for MemTransaction<'_> {
    #[allow(clippy::significant_drop_tightening)]
    async fn commit_tx(self) -> Result<()> {
        let mut data = self.db.data.write().expect("Poisoned rwlock");
        let mut data_copy = data.clone();
        for op in self.operations {
            match op {
                DatabaseOperation::Insert(insert_op) => {
                    anyhow::ensure!(
                        data_copy.insert(insert_op.key, insert_op.value) == insert_op.old_value,
                        "write-write conflict"
                    );
                }
                DatabaseOperation::Delete(delete_op) => {
                    anyhow::ensure!(
                        data_copy.remove(&delete_op.key) == delete_op.old_value,
                        "write-write conflict"
                    );
                }
            }
        }
        *data = data_copy;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
