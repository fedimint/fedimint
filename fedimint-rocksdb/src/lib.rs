use std::path::Path;

use anyhow::Result;
use fedimint_api::db::batch::{BatchItem, DbBatch};
use fedimint_api::db::{DatabaseTransaction, PrefixIter};
use fedimint_api::db::{IDatabase, IDatabaseTransaction};
pub use rocksdb;
use rocksdb::OptimisticTransactionDB;
use tracing::{error, trace};

#[derive(Debug)]
pub struct RocksDb(rocksdb::OptimisticTransactionDB);

pub struct RocksDbTransaction<'a>(rocksdb::Transaction<'a, rocksdb::OptimisticTransactionDB>);

impl RocksDb {
    pub fn open(db_path: impl AsRef<Path>) -> Result<RocksDb, rocksdb::Error> {
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::open_default(&db_path)?;
        Ok(RocksDb(db))
    }

    pub fn inner(&self) -> &rocksdb::OptimisticTransactionDB {
        &self.0
    }
}

impl From<rocksdb::OptimisticTransactionDB> for RocksDb {
    fn from(db: OptimisticTransactionDB) -> Self {
        RocksDb(db)
    }
}

impl From<RocksDb> for rocksdb::OptimisticTransactionDB {
    fn from(db: RocksDb) -> Self {
        db.0
    }
}

impl IDatabase for RocksDb {
    fn raw_insert_entry(&self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let val = self.inner().get(key).unwrap();
        self.inner().put(key, value)?;
        Ok(val)
    }

    fn raw_get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.inner().get(key)?)
    }

    fn raw_remove_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let val = self.inner().get(key).unwrap();
        self.inner().delete(key)?;
        Ok(val)
    }

    fn raw_find_by_prefix(&self, key_prefix: &[u8]) -> PrefixIter<'_> {
        let prefix = key_prefix.to_vec();
        Box::new(
            self.inner()
                .prefix_iterator(prefix.clone())
                .map_while(move |res| {
                    let (key_bytes, value_bytes) = res.expect("DB error");
                    // TODO: do not bump the MSRV with it just yet, change
                    // in a couple of months
                    #[allow(clippy::unnecessary_lazy_evaluations)]
                    key_bytes
                        .starts_with(&prefix)
                        .then(|| (key_bytes, value_bytes))
                })
                .map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()))
                .map(Ok),
        )
    }

    fn raw_apply_batch(&self, batch: DbBatch) -> Result<()> {
        let batch: Vec<_> = batch.into();
        let tx = self.inner().transaction();

        for change in batch.iter() {
            match change {
                BatchItem::InsertNewElement(element) => {
                    if tx.get(element.key.to_bytes()).unwrap().is_some() {
                        tx.put(element.key.to_bytes(), element.value.to_bytes())?;
                        error!("Database replaced element! This should not happen!");
                        trace!("Problematic key: {:?}", element.key);
                    } else {
                        tx.put(element.key.to_bytes(), element.value.to_bytes())?;
                    }
                }
                BatchItem::InsertElement(element) => {
                    tx.put(element.key.to_bytes(), element.value.to_bytes())?;
                }
                BatchItem::DeleteElement(key) => {
                    if tx.get(key.to_bytes()).unwrap().is_none() {
                        tx.delete(key.to_bytes())?;
                        error!("Database deleted absent element! This should not happen!");
                        trace!("Problematic key: {:?}", key);
                    } else {
                        tx.delete(key.to_bytes())?;
                    }
                }
                BatchItem::MaybeDeleteElement(key) => {
                    tx.delete(key.to_bytes())?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn begin_transaction(&self) -> DatabaseTransaction {
        RocksDbTransaction(self.0.transaction()).into()
    }
}

impl<'a> IDatabaseTransaction<'a> for RocksDbTransaction<'a> {
    fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let val = self.0.get(key).unwrap();
        self.0.put(key, value)?;
        Ok(val)
    }

    fn raw_get_bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(key)?)
    }

    fn raw_remove_entry(&mut self, key: &[u8]) -> Result<()> {
        self.0.delete(key)?;
        Ok(())
    }

    fn raw_find_by_prefix(&self, key_prefix: &[u8]) -> PrefixIter<'_> {
        let prefix = key_prefix.to_vec();
        Box::new(
            self.0
                .prefix_iterator(prefix.clone())
                .map_while(move |res| {
                    let (key_bytes, value_bytes) = res.expect("DB error");
                    key_bytes
                        .starts_with(&prefix)
                        .then_some((key_bytes, value_bytes))
                })
                .map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()))
                .map(Ok),
        )
    }

    fn commit_tx(self: Box<Self>) -> Result<()> {
        self.0.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::RocksDb;

    #[test_log::test]
    fn test_basic_rw() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();

        fedimint_api::db::test_db_impl(db.into());
    }

    #[test_log::test]
    fn test_basic_dbtx_rw() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();

        fedimint_api::db::test_dbtx_impl(db.into());
    }
}
