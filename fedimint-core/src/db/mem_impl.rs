use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Mutex;

use anyhow::Result;
use bitcoin_hashes::hex::ToHex;
use futures::{stream, StreamExt};
use macro_rules_attribute::apply;

use super::{
    IDatabase, IDatabaseTransaction, IDatabaseTransactionOps, ISingleUseDatabaseTransaction,
    SingleUseDatabaseTransaction,
};
use crate::async_trait_maybe_send;
use crate::db::PrefixStream;

#[derive(Debug, Default)]
pub struct DatabaseInsertOperation {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct DatabaseDeleteOperation {
    pub key: Vec<u8>,
}

#[derive(Debug)]
pub enum DatabaseOperation {
    Insert(DatabaseInsertOperation),
    Delete(DatabaseDeleteOperation),
}

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
            println!("{}: {}", key.to_hex(), value.to_hex());
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl IDatabase for MemDatabase {
    async fn begin_transaction<'a>(&'a self) -> Box<dyn ISingleUseDatabaseTransaction<'a>> {
        let db_copy = self.data.lock().unwrap().clone();
        let mut memtx = MemTransaction {
            operations: Vec::new(),
            tx_data: db_copy.clone(),
            db: self,
            savepoint: db_copy,
            num_pending_operations: 0,
            num_savepoint_operations: 0,
        };

        memtx.set_tx_savepoint().await.expect("can't fail");
        let single_use = SingleUseDatabaseTransaction::new(memtx);
        Box::new(single_use)
    }
}

// In-memory database transaction should only be used for test code and never
// for production as it doesn't properly implement MVCC
#[apply(async_trait_maybe_send!)]
impl<'a> IDatabaseTransactionOps<'a> for MemTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let val = self.raw_get_bytes(key).await;
        // Insert data from copy so we can read our own writes
        self.tx_data.insert(key.to_vec(), value.to_owned());
        self.operations
            .push(DatabaseOperation::Insert(DatabaseInsertOperation {
                key: key.to_vec(),
                value: value.to_owned(),
            }));
        self.num_pending_operations += 1;
        val
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
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
            .range::<Vec<u8>, _>((key_prefix.to_vec())..)
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
            .range::<Vec<u8>, _>((key_prefix.to_vec())..)
            .take_while(|(key, _)| key.starts_with(key_prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        data.sort_by(|a, b| a.cmp(b).reverse());

        Ok(Box::pin(stream::iter(data)))
    }

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
impl<'a> IDatabaseTransaction<'a> for MemTransaction<'a> {
    async fn commit_tx(self) -> Result<()> {
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
}

#[cfg(test)]
mod tests {
    use super::MemDatabase;
    use crate::core::ModuleInstanceId;
    use crate::db::Database;
    use crate::module::registry::ModuleDecoderRegistry;

    fn database() -> Database {
        Database::new(MemDatabase::new(), ModuleDecoderRegistry::default())
    }

    fn module_database(module_instance_id: ModuleInstanceId) -> Database {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        db.new_isolated(module_instance_id)
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_insert_elements() {
        fedimint_core::db::verify_insert_elements(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_nonexisting() {
        fedimint_core::db::verify_remove_nonexisting(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_existing() {
        fedimint_core::db::verify_remove_nonexisting(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_read_own_writes() {
        fedimint_core::db::verify_read_own_writes(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_prevent_dirty_reads() {
        fedimint_core::db::verify_prevent_dirty_reads(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_find_by_prefix() {
        fedimint_core::db::verify_find_by_prefix(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_commit() {
        fedimint_core::db::verify_commit(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_prevent_nonrepeatable_reads() {
        fedimint_core::db::verify_prevent_nonrepeatable_reads(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_rollback_to_savepoint() {
        fedimint_core::db::verify_rollback_to_savepoint(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_phantom_entry() {
        fedimint_core::db::verify_phantom_entry(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_by_prefix() {
        fedimint_core::db::verify_remove_by_prefix(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_module_dbtx() {
        fedimint_core::db::verify_module_prefix(database()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_module_db() {
        fedimint_core::db::verify_module_db(database(), module_database(1)).await;
    }
}
