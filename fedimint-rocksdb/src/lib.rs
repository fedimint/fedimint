use std::path::Path;

use anyhow::Result;
use fedimint_api::db::{DatabaseTransaction, PrefixIter};
use fedimint_api::db::{IDatabase, IDatabaseTransaction};
pub use rocksdb;
use rocksdb::{OptimisticTransactionDB, OptimisticTransactionOptions, WriteOptions};
use tracing::warn;

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
    fn begin_transaction(&self) -> DatabaseTransaction {
        let mut optimistic_options = OptimisticTransactionOptions::default();
        optimistic_options.set_snapshot(true);
        let mut tx: DatabaseTransaction = RocksDbTransaction(
            self.0
                .transaction_opt(&WriteOptions::default(), &optimistic_options),
        )
        .into();
        tx.set_tx_savepoint();
        tx
    }
}

impl<'a> IDatabaseTransaction<'a> for RocksDbTransaction<'a> {
    fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let val = self.0.get(key).unwrap();
        self.0.put(key, value)?;
        Ok(val)
    }

    fn raw_get_bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.snapshot().get(key)?)
    }

    fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let val = self.0.get(key).unwrap();
        self.0.delete(key)?;
        Ok(val)
    }

    fn raw_find_by_prefix(&self, key_prefix: &[u8]) -> PrefixIter<'_> {
        let prefix = key_prefix.to_vec();
        let mut options = rocksdb::ReadOptions::default();
        options.set_iterate_range(rocksdb::PrefixRange(prefix.clone()));
        let iter = self.0.snapshot().iterator_opt(
            rocksdb::IteratorMode::From(&prefix.clone(), rocksdb::Direction::Forward),
            options,
        );
        Box::new(
            iter.map_while(move |res| {
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

    fn rollback_tx_to_savepoint(&mut self) {
        match self.0.rollback_to_savepoint() {
            Ok(()) => {}
            _ => {
                warn!("Rolling back database transaction without a set savepoint");
            }
        }
    }

    fn set_tx_savepoint(&mut self) {
        self.0.set_savepoint();
    }
}

#[cfg(test)]
mod fedimint_rocksdb_tests {
    use crate::RocksDb;

    #[test_log::test]
    fn test_dbtx_insert_elements() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-insert-elements")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();
        fedimint_api::db::verify_insert_elements(db.into());
    }

    #[test_log::test]
    fn test_dbtx_remove_nonexisting() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-remove-nonexisting")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();
        fedimint_api::db::verify_remove_nonexisting(db.into());
    }

    #[test_log::test]
    fn test_dbtx_remove_existing() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-remove-existing")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();
        fedimint_api::db::verify_remove_nonexisting(db.into());
    }

    #[test_log::test]
    fn test_dbtx_read_own_writes() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-read-own-writes")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();
        fedimint_api::db::verify_read_own_writes(db.into());
    }

    #[test_log::test]
    fn test_dbtx_prevent_dirty_reads() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-prevent-dirty-reads")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();
        fedimint_api::db::verify_prevent_dirty_reads(db.into());
    }

    #[test_log::test]
    fn test_dbtx_find_by_prefix() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-find-by-prefix")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();
        fedimint_api::db::verify_find_by_prefix(db.into());
    }

    #[test_log::test]
    fn test_dbtx_commit() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-commit")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();
        fedimint_api::db::verify_commit(db.into());
    }

    #[test_log::test]
    fn test_dbtx_prevent_nonrepeatable_reads() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-prevent-nonrepeatable-reads")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();
        fedimint_api::db::verify_prevent_nonrepeatable_reads(db.into());
    }

    #[test_log::test]
    fn test_dbtx_rollback_to_savepoint() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-rollback-to-savepoint")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();
        fedimint_api::db::verify_rollback_to_savepoint(db.into());
    }

    #[test_log::test]
    fn test_dbtx_phantom_entry() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-phantom-entry")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();
        fedimint_api::db::verify_phantom_entry(db.into());
    }

    #[test_log::test]
    fn test_dbtx_write_conflict() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-write-conflict")
            .tempdir()
            .unwrap();

        let db = RocksDb::open(path).unwrap();
        fedimint_api::db::expect_write_conflict(db.into());
    }
}
