use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use fedimint_core::db::{IDatabase, IDatabaseTransaction, PrefixStream};
use futures::stream;
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
    async fn begin_transaction<'a>(&'a self) -> Box<dyn IDatabaseTransaction<'a>> {
        let mut optimistic_options = OptimisticTransactionOptions::default();
        optimistic_options.set_snapshot(true);
        let mut rocksdb_tx = RocksDbTransaction(
            self.0
                .transaction_opt(&WriteOptions::default(), &optimistic_options),
        );
        rocksdb_tx.set_tx_savepoint().await;
        Box::new(rocksdb_tx)
    }
}

#[async_trait]
impl<'a> IDatabaseTransaction<'a> for RocksDbTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        fedimint_core::task::block_in_place(|| {
            let val = self.0.get(key).unwrap();
            self.0.put(key, value)?;
            Ok(val)
        })
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        fedimint_core::task::block_in_place(|| Ok(self.0.snapshot().get(key)?))
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        fedimint_core::task::block_in_place(|| {
            let val = self.0.get(key).unwrap();
            self.0.delete(key)?;
            Ok(val)
        })
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> PrefixStream<'_> {
        fedimint_core::task::block_in_place(|| {
            let prefix = key_prefix.to_vec();
            let mut options = rocksdb::ReadOptions::default();
            options.set_iterate_range(rocksdb::PrefixRange(prefix.clone()));
            let iter = self.0.snapshot().iterator_opt(
                rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward),
                options,
            );

            let rocksdb_iter = iter
                .map_while(move |res| {
                    let (key_bytes, value_bytes) = res.expect("DB error");
                    key_bytes
                        .starts_with(&prefix)
                        .then_some((key_bytes, value_bytes))
                })
                .map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()));

            Box::pin(stream::iter(rocksdb_iter))
        })
    }

    async fn commit_tx(self: Box<Self>) -> Result<()> {
        fedimint_core::task::block_in_place(|| {
            self.0.commit()?;
            Ok(())
        })
    }

    async fn rollback_tx_to_savepoint(&mut self) {
        fedimint_core::task::block_in_place(|| match self.0.rollback_to_savepoint() {
            Ok(()) => {}
            _ => {
                warn!("Rolling back database transaction without a set savepoint");
            }
        })
    }

    async fn set_tx_savepoint(&mut self) {
        fedimint_core::task::block_in_place(|| {
            self.0.set_savepoint();
        })
    }
}

#[async_trait]
impl IDatabaseTransaction<'_> for RocksDbReadOnly {
    async fn raw_insert_bytes(&mut self, _key: &[u8], _value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        panic!("Cannot insert into a read only transaction");
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        fedimint_core::task::block_in_place(|| Ok(self.0.get(key)?))
    }

    async fn raw_remove_entry(&mut self, _key: &[u8]) -> Result<Option<Vec<u8>>> {
        panic!("Cannot remove from a read only transaction");
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> PrefixStream<'_> {
        fedimint_core::task::block_in_place(|| {
            let prefix = key_prefix.to_vec();

            let rocksdb_iter = self
                .0
                .prefix_iterator(prefix.clone())
                .map_while(move |res| {
                    let (key_bytes, value_bytes) = res.expect("DB error");
                    key_bytes
                        .starts_with(&prefix)
                        .then_some((key_bytes, value_bytes))
                })
                .map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()));

            Box::pin(stream::iter(rocksdb_iter))
        })
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
    use fedimint_core::{db::Database, module::registry::ModuleDecoderRegistry};

    use crate::RocksDb;

    fn open_temp_db(temp_path: &str) -> Database {
        let path = tempfile::Builder::new()
            .prefix(temp_path)
            .tempdir()
            .unwrap();

        Database::new(
            RocksDb::open(path).unwrap(),
            ModuleDecoderRegistry::default(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_insert_elements() {
        fedimint_core::db::verify_insert_elements(open_temp_db("fcb-rocksdb-test-insert-elements"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_remove_nonexisting() {
        fedimint_core::db::verify_remove_nonexisting(open_temp_db(
            "fcb-rocksdb-test-remove-nonexisting",
        ))
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_remove_existing() {
        fedimint_core::db::verify_remove_existing(open_temp_db("fcb-rocksdb-test-remove-existing"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_read_own_writes() {
        fedimint_core::db::verify_read_own_writes(open_temp_db("fcb-rocksdb-test-read-own-writes"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_prevent_dirty_reads() {
        fedimint_core::db::verify_prevent_dirty_reads(open_temp_db(
            "fcb-rocksdb-test-prevent-dirty-reads",
        ))
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_find_by_prefix() {
        fedimint_core::db::verify_find_by_prefix(open_temp_db("fcb-rocksdb-test-find-by-prefix"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_commit() {
        fedimint_core::db::verify_commit(open_temp_db("fcb-rocksdb-test-commit")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_prevent_nonrepeatable_reads() {
        fedimint_core::db::verify_prevent_nonrepeatable_reads(open_temp_db(
            "fcb-rocksdb-test-prevent-nonrepeatable-reads",
        ))
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_rollback_to_savepoint() {
        fedimint_core::db::verify_rollback_to_savepoint(open_temp_db(
            "fcb-rocksdb-test-rollback-to-savepoint",
        ))
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_phantom_entry() {
        fedimint_core::db::verify_phantom_entry(open_temp_db("fcb-rocksdb-test-phantom-entry"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_write_conflict() {
        fedimint_core::db::expect_write_conflict(open_temp_db("fcb-rocksdb-test-write-conflict"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_remove_by_prefix() {
        fedimint_core::db::verify_remove_by_prefix(open_temp_db(
            "fcb-rocksdb-test-remove-by-prefix",
        ))
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_module_dbtx() {
        fedimint_core::db::verify_module_prefix(open_temp_db("fcb-rocksdb-test-module-prefix"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_module_db() {
        let module_instance_id = 1;
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-module-db-prefix")
            .tempdir()
            .unwrap();

        let module_db = Database::new(
            RocksDb::open(path).unwrap(),
            ModuleDecoderRegistry::default(),
        );

        fedimint_core::db::verify_module_db(
            open_temp_db("fcb-rocksdb-test-module-db"),
            module_db.new_isolated(module_instance_id),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[should_panic(expected = "Cannot isolate and already isolated database.")]
    async fn test_cannot_isolate_already_isolated_db() {
        let module_instance_id = 1;
        let db = open_temp_db("rocksdb-test-already-isolated").new_isolated(module_instance_id);

        // try to isolate the database again
        let module_instance_id = 2;
        db.new_isolated(module_instance_id);
    }
}
