//! Uses immutable data structures and saves to indexeddb on commit.
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use fedimint_core::db::{
    IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase, IRawDatabaseTransaction,
    PrefixStream,
};
use fedimint_core::{apply, async_trait_maybe_send};
use futures::lock::Mutex;
use futures::stream;
use imbl::OrdMap;
use rexie::{Rexie, TransactionMode};
use wasm_bindgen::JsCast;

pub fn rexie_to_anyhow(e: rexie::Error) -> anyhow::Error {
    anyhow::anyhow!(e.to_string())
}

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
pub struct MemAndIndexedDb {
    data: Arc<Mutex<OrdMap<Vec<u8>, Vec<u8>>>>,
    idb: Arc<Rexie>,
}

impl Debug for MemAndIndexedDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemDatabase").finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct MemAndIndexedDbTransaction<'a> {
    operations: Vec<DatabaseOperation>,
    tx_data: OrdMap<Vec<u8>, Vec<u8>>,
    db: &'a MemAndIndexedDb,
    savepoint: OrdMap<Vec<u8>, Vec<u8>>,
    num_pending_operations: usize,
    num_savepoint_operations: usize,
}

impl MemAndIndexedDb {
    pub async fn new(name: &str) -> Result<Self> {
        let idb = rexie::Rexie::builder(name)
            .add_object_store(rexie::ObjectStore::new("default"))
            .build()
            .await
            .map_err(rexie_to_anyhow)?;
        let idb = Arc::new(idb);
        let mut data = OrdMap::new();

        let idb_tx = idb
            .transaction(&["default"], TransactionMode::ReadWrite)
            .map_err(rexie_to_anyhow)?;

        let idb_store = idb_tx.store("default").map_err(rexie_to_anyhow)?;
        let entries = idb_store
            .get_all(None, None, None, None)
            .await
            .map_err(rexie_to_anyhow)?;

        for (key, value) in entries {
            let key = js_sys::Uint8Array::new(&key).to_vec();
            let value = value.dyn_into::<js_sys::Uint8Array>().unwrap().to_vec();
            data.insert(key, value);
        }
        Ok(Self {
            data: Arc::new(Mutex::new(data)),
            idb,
        })
    }

    pub async fn delete(self) -> Result<()> {
        Rexie::delete(&self.idb.name())
            .await
            .map_err(|e| anyhow::anyhow!("Error deleting database: {e}"))
    }
}

#[apply(async_trait_maybe_send!)]
impl IRawDatabase for MemAndIndexedDb {
    type Transaction<'a> = MemAndIndexedDbTransaction<'a>;
    async fn begin_transaction<'a>(&'a self) -> MemAndIndexedDbTransaction<'a> {
        let db_clone = self.data.lock().await.clone();
        let mut memtx = MemAndIndexedDbTransaction {
            operations: Vec::new(),
            tx_data: db_clone.clone(),
            db: self,
            savepoint: db_clone,
            num_pending_operations: 0,
            num_savepoint_operations: 0,
        };

        memtx
            .set_tx_savepoint()
            .await
            .expect("MemTransaction never fails");
        memtx
    }

    fn checkpoint(&self, _: &std::path::Path) -> Result<(), anyhow::Error> {
        unimplemented!()
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a> IDatabaseTransactionOpsCore for MemAndIndexedDbTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let val = IDatabaseTransactionOpsCore::raw_get_bytes(self, key).await;
        // Insert data from copy so we can read our own writes
        let old_value = self.tx_data.insert(key.to_vec(), value.to_vec());
        self.operations
            .push(DatabaseOperation::Insert(DatabaseInsertOperation {
                key: key.to_vec(),
                value: value.to_vec(),
                old_value,
            }));
        self.num_pending_operations += 1;
        val
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

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        let data = self
            .tx_data
            .range::<_, Vec<u8>>((key_prefix.to_vec())..)
            .take_while(|(key, _)| key.starts_with(key_prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();

        Ok(Box::pin(stream::iter(data)))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> anyhow::Result<()> {
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
            self.num_pending_operations += 1;
        }
        Ok(())
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
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

#[apply(async_trait_maybe_send!)]
impl<'a> IDatabaseTransactionOps for MemAndIndexedDbTransaction<'a> {
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

// In-memory database transaction should only be used for test code and never
// for production as it doesn't properly implement MVCC
#[apply(async_trait_maybe_send!)]
impl<'a> IRawDatabaseTransaction for MemAndIndexedDbTransaction<'a> {
    async fn commit_tx(self) -> Result<()> {
        let mut data = self.db.data.lock().await;
        let mut data_new = data.clone();
        let idb_tx = self
            .db
            .idb
            .transaction(&["default"], TransactionMode::ReadWrite)
            .map_err(rexie_to_anyhow)?;

        let idb_store = idb_tx.store("default").map_err(rexie_to_anyhow)?;

        let result = async {
            for op in self.operations {
                match op {
                    DatabaseOperation::Insert(insert_op) => {
                        let key = js_sys::Uint8Array::from(&insert_op.key[..]);
                        let value = js_sys::Uint8Array::from(&insert_op.value[..]);
                        idb_store
                            .put(&value, Some(&key))
                            .await
                            .map_err(rexie_to_anyhow)?;
                        let old_value = data_new.insert(insert_op.key, insert_op.value);
                        anyhow::ensure!(old_value == insert_op.old_value, "write-write conflict");
                    }
                    DatabaseOperation::Delete(delete_op) => {
                        let key = js_sys::Uint8Array::from(&delete_op.key[..]);
                        idb_store.delete(&key).await.map_err(rexie_to_anyhow)?;
                        let old_value = data_new.remove(&delete_op.key);
                        anyhow::ensure!(old_value == delete_op.old_value, "write-write conflict");
                    }
                }
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                idb_tx
                    .commit()
                    .await
                    .map_err(rexie_to_anyhow)
                    .context("indexeddb commit failed")?;
                // commit the data to memdb
                *data = data_new;
                Ok(())
            }
            Err(e) => {
                idb_tx
                    .abort()
                    .await
                    .map_err(rexie_to_anyhow)
                    .context("indexeddb abort failed")?;
                Err(e)
            }
        }
    }
}
