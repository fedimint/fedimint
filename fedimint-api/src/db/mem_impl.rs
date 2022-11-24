use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Mutex;

use anyhow::Result;
use async_trait::async_trait;
use fedimint_api::ModuleRegistry;

use super::{
    DatabaseDeleteOperation, DatabaseInsertOperation, DatabaseOperation, DatabaseTransaction,
    IDatabase, IDatabaseTransaction,
};
use crate::core::Decoder;
use crate::db::PrefixIter;

#[derive(Debug, Default)]
pub struct MemDatabase {
    data: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
}

#[derive(Debug)]
pub struct MemTransaction<'a> {
    operations: Vec<DatabaseOperation>,
    tx_data: BTreeMap<Vec<u8>, Vec<u8>>,
    db: &'a MemDatabase,
    savepoint: BTreeMap<Vec<u8>, Vec<u8>>,
    num_pending_operations: usize,
    num_savepoint_operations: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DummyError;

impl MemDatabase {
    pub fn new() -> MemDatabase {
        Default::default()
    }

    pub fn dump_db(&self) {
        let data = self.data.lock().unwrap();
        let data_iter = data.iter();
        for (key, value) in data_iter {
            eprintln!("{}: {}", hex::encode(key), hex::encode(value));
        }
    }
}

impl IDatabase for MemDatabase {
    fn begin_transaction(&self, decoders: ModuleRegistry<Decoder>) -> DatabaseTransaction {
        let db_copy = self.data.lock().unwrap().clone();
        let memtx = MemTransaction {
            operations: Vec::new(),
            tx_data: db_copy.clone(),
            db: self,
            savepoint: db_copy,
            num_pending_operations: 0,
            num_savepoint_operations: 0,
        };

        let mut tx = DatabaseTransaction::new(memtx, decoders);
        tx.set_tx_savepoint();
        tx
    }
}

// In-memory database transaction should only be used for test code and never for production
// as it doesn't properly implement MVCC
#[async_trait]
impl<'a> IDatabaseTransaction<'a> for MemTransaction<'a> {
    fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let val = self.raw_get_bytes(key);
        // Insert data from copy so we can read our own writes
        self.tx_data.insert(key.to_vec(), value.clone());
        self.operations
            .push(DatabaseOperation::Insert(DatabaseInsertOperation {
                key: key.to_vec(),
                value,
            }));
        self.num_pending_operations += 1;
        val
    }

    fn raw_get_bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.tx_data.get(key).cloned())
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // Remove data from copy so we can read our own writes
        let ret = self.tx_data.remove(&key.to_vec());
        self.operations
            .push(DatabaseOperation::Delete(DatabaseDeleteOperation {
                key: key.to_vec(),
            }));
        self.num_pending_operations += 1;
        Ok(ret)
    }

    fn raw_find_by_prefix(&self, key_prefix: &[u8]) -> PrefixIter<'_> {
        let mut data = self
            .tx_data
            .range::<Vec<u8>, _>((key_prefix.to_vec())..)
            .take_while(|(key, _)| key.starts_with(key_prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        data.reverse();

        Box::new(MemDbIter { data })
    }

    async fn commit_tx(self: Box<Self>) -> Result<()> {
        for op in self.operations {
            match op {
                DatabaseOperation::Insert(insert_op) => {
                    self.db
                        .data
                        .lock()
                        .unwrap()
                        .insert(insert_op.key, insert_op.value);
                }
                DatabaseOperation::Delete(delete_op) => {
                    self.db.data.lock().unwrap().remove(&delete_op.key);
                }
            }
        }

        Ok(())
    }

    async fn rollback_tx_to_savepoint(&mut self) {
        self.tx_data = self.savepoint.clone();

        // Remove any pending operations beyond the savepoint
        let removed_ops = self.num_pending_operations - self.num_savepoint_operations;
        for _i in 0..removed_ops {
            self.operations.pop();
        }
    }

    fn set_tx_savepoint(&mut self) {
        self.savepoint = self.tx_data.clone();
        self.num_savepoint_operations = self.num_pending_operations;
    }
}

struct MemDbIter {
    data: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Iterator for MemDbIter {
    type Item = Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.data.pop().map(Result::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::MemDatabase;

    #[test_log::test(tokio::test)]
    async fn test_dbtx_insert_elements() {
        fedimint_api::db::verify_insert_elements(MemDatabase::new().into()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_nonexisting() {
        fedimint_api::db::verify_remove_nonexisting(MemDatabase::new().into()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_existing() {
        fedimint_api::db::verify_remove_nonexisting(MemDatabase::new().into()).await;
    }

    #[test_log::test]
    fn test_dbtx_read_own_writes() {
        fedimint_api::db::verify_read_own_writes(MemDatabase::new().into());
    }

    #[test_log::test]
    fn test_dbtx_prevent_dirty_reads() {
        fedimint_api::db::verify_prevent_dirty_reads(MemDatabase::new().into());
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_find_by_prefix() {
        fedimint_api::db::verify_find_by_prefix(MemDatabase::new().into()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_commit() {
        fedimint_api::db::verify_commit(MemDatabase::new().into()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_prevent_nonrepeatable_reads() {
        fedimint_api::db::verify_prevent_nonrepeatable_reads(MemDatabase::new().into()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_rollback_to_savepoint() {
        fedimint_api::db::verify_rollback_to_savepoint(MemDatabase::new().into()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_phantom_entry() {
        fedimint_api::db::verify_phantom_entry(MemDatabase::new().into()).await;
    }
}
