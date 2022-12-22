use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use fedimint_api::db::{DatabaseTransaction, PrefixIter, ReadOnlyDatabaseTransaction};
use fedimint_api::db::{IDatabase, IDatabaseTransaction};
use fedimint_api::module::registry::ModuleDecoderRegistry;
pub use rocksdb;
use rocksdb::{OptimisticTransactionDB, OptimisticTransactionOptions, WriteOptions};
use tracing::warn;

#[derive(Debug)]
pub struct RocksDb(rocksdb::OptimisticTransactionDB);

pub struct RocksDbReadOnly(rocksdb::DB);

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

impl RocksDbReadOnly {
    pub fn open_read_only(db_path: impl AsRef<Path>) -> Result<RocksDbReadOnly, rocksdb::Error> {
        let opts = rocksdb::Options::default();
        let db = rocksdb::DB::open_for_read_only(&opts, db_path, false)?;
        Ok(RocksDbReadOnly(db))
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

#[async_trait]
impl IDatabase for RocksDb {
    async fn begin_transaction(&self, decoders: ModuleDecoderRegistry) -> DatabaseTransaction {
        let mut optimistic_options = OptimisticTransactionOptions::default();
        optimistic_options.set_snapshot(true);
        let rocksdb_tx = RocksDbTransaction(
            self.0
                .transaction_opt(&WriteOptions::default(), &optimistic_options),
        );
        let mut tx = DatabaseTransaction::new(rocksdb_tx, decoders);
        tx.set_tx_savepoint().await;
        tx
    }

    async fn begin_readonly_transaction(
        &self,
        decoders: ModuleDecoderRegistry,
    ) -> ReadOnlyDatabaseTransaction {
        let mut optimistic_options = OptimisticTransactionOptions::default();
        optimistic_options.set_snapshot(true);
        let rocksdb_tx = RocksDbTransaction(
            self.0
                .transaction_opt(&WriteOptions::default(), &optimistic_options),
        );
        ReadOnlyDatabaseTransaction::new(rocksdb_tx, decoders)
    }
}

#[async_trait]
impl<'a> IDatabaseTransaction<'a> for RocksDbTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let val = self.0.get(key).unwrap();
        self.0.put(key, value)?;
        Ok(val)
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.snapshot().get(key)?)
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let val = self.0.get(key).unwrap();
        self.0.delete(key)?;
        Ok(val)
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> PrefixIter<'_> {
        let prefix = key_prefix.to_vec();
        let mut options = rocksdb::ReadOptions::default();
        options.set_iterate_range(rocksdb::PrefixRange(prefix.clone()));
        let iter = self.0.snapshot().iterator_opt(
            rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward),
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

    async fn commit_tx(self: Box<Self>) -> Result<()> {
        self.0.commit()?;
        Ok(())
    }

    async fn rollback_tx_to_savepoint(&mut self) {
        match self.0.rollback_to_savepoint() {
            Ok(()) => {}
            _ => {
                warn!("Rolling back database transaction without a set savepoint");
            }
        }
    }

    async fn set_tx_savepoint(&mut self) {
        self.0.set_savepoint();
    }
}

#[async_trait]
impl IDatabaseTransaction<'_> for RocksDbReadOnly {
    async fn raw_insert_bytes(&mut self, _key: &[u8], _value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        panic!("Cannot insert into a read only transaction");
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(key)?)
    }

    async fn raw_remove_entry(&mut self, _key: &[u8]) -> Result<Option<Vec<u8>>> {
        panic!("Cannot remove from a read only transaction");
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> PrefixIter<'_> {
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

    async fn commit_tx(self: Box<Self>) -> Result<()> {
        panic!("Cannot commit a read only transaction");
    }

    async fn rollback_tx_to_savepoint(&mut self) {
        panic!("Cannot rollback a read only transaction");
    }

    async fn set_tx_savepoint(&mut self) {
        panic!("Cannot set a savepoint in a read only transaction");
    }
}

#[cfg(test)]
mod fedimint_rocksdb_tests {
    use crate::RocksDb;

    fn open_temp_db(temp_path: &str) -> RocksDb {
        let path = tempfile::Builder::new()
            .prefix(temp_path)
            .tempdir()
            .unwrap();

        RocksDb::open(path).unwrap()
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_insert_elements() {
        fedimint_api::db::verify_insert_elements(
            open_temp_db("fcb-rocksdb-test-insert-elements").into(),
        )
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_nonexisting() {
        fedimint_api::db::verify_remove_nonexisting(
            open_temp_db("fcb-rocksdb-test-remove-nonexisting").into(),
        )
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_existing() {
        fedimint_api::db::verify_remove_existing(
            open_temp_db("fcb-rocksdb-test-remove-existing").into(),
        )
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_read_own_writes() {
        fedimint_api::db::verify_read_own_writes(
            open_temp_db("fcb-rocksdb-test-read-own-writes").into(),
        )
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_prevent_dirty_reads() {
        fedimint_api::db::verify_prevent_dirty_reads(
            open_temp_db("fcb-rocksdb-test-prevent-dirty-reads").into(),
        )
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_find_by_prefix() {
        fedimint_api::db::verify_find_by_prefix(
            open_temp_db("fcb-rocksdb-test-find-by-prefix").into(),
        )
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_commit() {
        fedimint_api::db::verify_commit(open_temp_db("fcb-rocksdb-test-commit").into()).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_prevent_nonrepeatable_reads() {
        fedimint_api::db::verify_prevent_nonrepeatable_reads(
            open_temp_db("fcb-rocksdb-test-prevent-nonrepeatable-reads").into(),
        )
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_rollback_to_savepoint() {
        fedimint_api::db::verify_rollback_to_savepoint(
            open_temp_db("fcb-rocksdb-test-rollback-to-savepoint").into(),
        )
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_phantom_entry() {
        fedimint_api::db::verify_phantom_entry(
            open_temp_db("fcb-rocksdb-test-phantom-entry").into(),
        )
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_write_conflict() {
        fedimint_api::db::expect_write_conflict(
            open_temp_db("fcb-rocksdb-test-write-conflict").into(),
        )
        .await;
    }
}
