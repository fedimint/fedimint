#![allow(where_clauses_object_safety)] // https://github.com/dtolnay/async-trait/issues/228
use std::path::Path;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use fedimint_core::db::{
    IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase, IRawDatabaseTransaction,
    PrefixStream,
};
use futures::stream;
pub use rocksdb;
use rocksdb::{OptimisticTransactionDB, OptimisticTransactionOptions, WriteOptions};
use tracing::debug;

#[derive(Debug)]
pub struct RocksDb(rocksdb::OptimisticTransactionDB);

pub struct RocksDbTransaction<'a>(rocksdb::Transaction<'a, rocksdb::OptimisticTransactionDB>);

impl RocksDb {
    pub fn open(db_path: impl AsRef<Path>) -> anyhow::Result<RocksDb> {
        let opts = get_default_options()?;
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::open(&opts, &db_path)?;
        Ok(RocksDb(db))
    }

    pub fn inner(&self) -> &rocksdb::OptimisticTransactionDB {
        &self.0
    }
}

fn is_power_of_two(num: usize) -> bool {
    num.count_ones() == 1
}

#[test]
fn is_power_of_two_sanity() {
    assert!(!is_power_of_two(0));
    assert!(is_power_of_two(1));
    assert!(is_power_of_two(2));
    assert!(!is_power_of_two(3));
    assert!(is_power_of_two(4));
    assert!(!is_power_of_two(5));
    assert!(is_power_of_two(2 << 10));
    assert!(!is_power_of_two((2 << 10) + 1));
}

fn get_default_options() -> anyhow::Result<rocksdb::Options> {
    let mut opts = rocksdb::Options::default();
    const VAR_NAME: &str = "FM_ROCKSDB_WRITE_BUFFER_SIZE";
    if let Ok(var) = std::env::var(VAR_NAME) {
        debug!(var, "Using custom write buffer size");
        let size: usize =
            FromStr::from_str(&var).with_context(|| format!("Could not parse {VAR_NAME}"))?;
        if !is_power_of_two(size) {
            bail!("{} is not a power of 2", VAR_NAME);
        }
        opts.set_write_buffer_size(size);
    }
    opts.create_if_missing(true);
    Ok(opts)
}

#[derive(Debug)]
pub struct RocksDbReadOnly(rocksdb::DB);

pub struct RocksDbReadOnlyTransaction<'a>(&'a rocksdb::DB);

impl RocksDbReadOnly {
    pub fn open_read_only(db_path: impl AsRef<Path>) -> anyhow::Result<RocksDbReadOnly> {
        let opts = get_default_options()?;
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

// When finding by prefix iterating in Reverse order, we need to start from
// "prefix+1" instead of "prefix", using lexicographic ordering. See the tests
// below.
// Will return None if there is no next prefix (i.e prefix is already the last
// possible/max one)
fn next_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut next_prefix = prefix.to_vec();
    let mut is_last_prefix = true;
    for i in (0..next_prefix.len()).rev() {
        next_prefix[i] = next_prefix[i].wrapping_add(1);
        if next_prefix[i] > 0 {
            is_last_prefix = false;
            break;
        }
    }
    if is_last_prefix {
        // The given prefix is already the last/max prefix, so there is no next prefix,
        // return None to represent that
        None
    } else {
        Some(next_prefix)
    }
}

#[async_trait]
impl IRawDatabase for RocksDb {
    type Transaction<'a> = RocksDbTransaction<'a>;
    async fn begin_transaction<'a>(&'a self) -> RocksDbTransaction {
        let mut optimistic_options = OptimisticTransactionOptions::default();
        optimistic_options.set_snapshot(true);
        let mut rocksdb_tx = RocksDbTransaction(
            self.0
                .transaction_opt(&WriteOptions::default(), &optimistic_options),
        );
        rocksdb_tx
            .set_tx_savepoint()
            .await
            .expect("setting tx savepoint failed");

        rocksdb_tx
    }
}

#[async_trait]
impl IRawDatabase for RocksDbReadOnly {
    type Transaction<'a> = RocksDbReadOnlyTransaction<'a>;
    async fn begin_transaction<'a>(&'a self) -> RocksDbReadOnlyTransaction<'a> {
        RocksDbReadOnlyTransaction(&self.0)
    }
}

#[async_trait]
impl<'a> IDatabaseTransactionOpsCore for RocksDbTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
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

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        // turn an `iter` into a `Stream` where every `next` is ran inside
        // `block_in_place` to offload the blocking calls
        fn convert_to_async_stream<'i, I>(iter: I) -> impl futures::Stream<Item = I::Item>
        where
            I: Iterator + Send + 'i,
            I::Item: Send,
        {
            stream::unfold(iter, |mut iter| async move {
                tokio::task::block_in_place(move || {
                    let item = iter.next();
                    item.map(move |item| (item, iter))
                })
            })
        }

        Ok(fedimint_core::task::block_in_place(|| {
            let prefix = key_prefix.to_vec();
            let mut options = rocksdb::ReadOptions::default();
            options.set_iterate_range(rocksdb::PrefixRange(prefix.clone()));
            let iter = self.0.snapshot().iterator_opt(
                rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward),
                options,
            );
            let rocksdb_iter = iter.map_while(move |res| {
                let (key_bytes, value_bytes) = res.expect("Error reading from RocksDb");
                key_bytes
                    .starts_with(&prefix)
                    .then_some((key_bytes.to_vec(), value_bytes.to_vec()))
            });
            Box::pin(convert_to_async_stream(rocksdb_iter))
        }))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> anyhow::Result<()> {
        fedimint_core::task::block_in_place(|| {
            // Note: delete_range is not supported in Transactions :/
            let mut options = rocksdb::ReadOptions::default();
            options.set_iterate_range(rocksdb::PrefixRange(key_prefix.to_owned()));
            let iter = self
                .0
                .snapshot()
                .iterator_opt(
                    rocksdb::IteratorMode::From(key_prefix, rocksdb::Direction::Forward),
                    options,
                )
                .map_while(move |res| {
                    res.map(|(key_bytes, _)| {
                        key_bytes
                            .starts_with(key_prefix)
                            .then_some(key_bytes.to_vec())
                    })
                    .transpose()
                });

            for item in iter {
                let key = item?;
                self.0.delete(key)?;
            }

            Ok(())
        })
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        let prefix = key_prefix.to_vec();
        let next_prefix = next_prefix(&prefix);
        let iterator_mode = if let Some(next_prefix) = &next_prefix {
            rocksdb::IteratorMode::From(next_prefix, rocksdb::Direction::Reverse)
        } else {
            rocksdb::IteratorMode::End
        };
        Ok(fedimint_core::task::block_in_place(|| {
            let mut options = rocksdb::ReadOptions::default();
            options.set_iterate_range(rocksdb::PrefixRange(prefix.clone()));
            let iter = self.0.snapshot().iterator_opt(iterator_mode, options);
            let rocksdb_iter = iter.map_while(move |res| {
                let (key_bytes, value_bytes) = res.expect("Error reading from RocksDb");
                key_bytes
                    .starts_with(&prefix)
                    .then_some((key_bytes.to_vec(), value_bytes.to_vec()))
            });
            Box::pin(stream::iter(rocksdb_iter))
        }))
    }
}

#[async_trait]
impl<'a> IDatabaseTransactionOps for RocksDbTransaction<'a> {
    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        Ok(fedimint_core::task::block_in_place(|| {
            self.0.rollback_to_savepoint()
        })?)
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        fedimint_core::task::block_in_place(|| self.0.set_savepoint());

        Ok(())
    }
}

#[async_trait]
impl<'a> IRawDatabaseTransaction for RocksDbTransaction<'a> {
    async fn commit_tx(self) -> Result<()> {
        fedimint_core::task::block_in_place(|| {
            self.0.commit()?;
            Ok(())
        })
    }
}

#[async_trait]
impl<'a> IDatabaseTransactionOpsCore for RocksDbReadOnlyTransaction<'a> {
    async fn raw_insert_bytes(&mut self, _key: &[u8], _value: &[u8]) -> Result<Option<Vec<u8>>> {
        panic!("Cannot insert into a read only transaction");
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        fedimint_core::task::block_in_place(|| Ok(self.0.get(key)?))
    }

    async fn raw_remove_entry(&mut self, _key: &[u8]) -> Result<Option<Vec<u8>>> {
        panic!("Cannot remove from a read only transaction");
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        Ok(fedimint_core::task::block_in_place(|| {
            let prefix = key_prefix.to_vec();
            let rocksdb_iter = self
                .0
                .prefix_iterator(prefix.clone())
                .map_while(move |res| {
                    let (key_bytes, value_bytes) = res.expect("Error reading from RocksDb");
                    key_bytes
                        .starts_with(&prefix)
                        .then_some((key_bytes, value_bytes))
                })
                .map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()));
            Box::pin(stream::iter(rocksdb_iter))
        }))
    }

    async fn raw_remove_by_prefix(&mut self, _key_prefix: &[u8]) -> anyhow::Result<()> {
        panic!("Cannot remove from a read only transaction");
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        let prefix = key_prefix.to_vec();
        let next_prefix = next_prefix(&prefix);
        let iterator_mode = if let Some(next_prefix) = &next_prefix {
            rocksdb::IteratorMode::From(next_prefix, rocksdb::Direction::Reverse)
        } else {
            rocksdb::IteratorMode::End
        };
        Ok(fedimint_core::task::block_in_place(|| {
            let mut options = rocksdb::ReadOptions::default();
            options.set_iterate_range(rocksdb::PrefixRange(prefix.clone()));
            let iter = self.0.snapshot().iterator_opt(iterator_mode, options);
            let rocksdb_iter = iter
                .map_while(move |res| {
                    let (key_bytes, value_bytes) = res.expect("Error reading from RocksDb");
                    key_bytes
                        .starts_with(&prefix)
                        .then_some((key_bytes, value_bytes))
                })
                .map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()));
            Box::pin(stream::iter(rocksdb_iter))
        }))
    }
}

#[async_trait]
impl<'a> IDatabaseTransactionOps for RocksDbReadOnlyTransaction<'a> {
    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        panic!("Cannot rollback a read only transaction");
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        panic!("Cannot set a savepoint in a read only transaction");
    }
}

#[async_trait]
impl<'a> IRawDatabaseTransaction for RocksDbReadOnlyTransaction<'a> {
    async fn commit_tx(self) -> Result<()> {
        panic!("Cannot commit a read only transaction");
    }
}

#[cfg(test)]
mod fedimint_rocksdb_tests {
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::{impl_db_lookup, impl_db_record};
    use futures::StreamExt;

    use super::*;

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
            module_db.with_prefix_module_id(module_instance_id),
        )
        .await;
    }

    #[test]
    fn test_next_prefix() {
        // Note: although we are testing the general case of a vector with N elements,
        // the prefixes currently use N = 1
        assert_eq!(next_prefix(&[1, 2, 3]).unwrap(), vec![1, 2, 4]);
        assert_eq!(next_prefix(&[1, 2, 254]).unwrap(), vec![1, 2, 255]);
        assert_eq!(next_prefix(&[1, 2, 255]).unwrap(), vec![1, 3, 0]);
        assert_eq!(next_prefix(&[1, 255, 255]).unwrap(), vec![2, 0, 0]);
        // this is a "max" prefix
        assert!(next_prefix(&[255, 255, 255]).is_none());
        // these are the common case
        assert_eq!(next_prefix(&[0]).unwrap(), vec![1]);
        assert_eq!(next_prefix(&[254]).unwrap(), vec![255]);
        assert!(next_prefix(&[255]).is_none()); // this is a "max" prefix
    }

    #[repr(u8)]
    #[derive(Clone)]
    pub enum TestDbKeyPrefix {
        Test = 254,
        MaxTest = 255,
    }

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
    pub(super) struct TestKey(pub Vec<u8>);

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
    pub(super) struct TestVal(pub Vec<u8>);

    #[derive(Debug, Encodable, Decodable)]
    struct DbPrefixTestPrefix;

    impl_db_record!(
        key = TestKey,
        value = TestVal,
        db_prefix = TestDbKeyPrefix::Test,
        notify_on_modify = true,
    );
    impl_db_lookup!(key = TestKey, query_prefix = DbPrefixTestPrefix);

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
    pub(super) struct TestKey2(pub Vec<u8>);

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
    pub(super) struct TestVal2(pub Vec<u8>);

    #[derive(Debug, Encodable, Decodable)]
    struct DbPrefixTestPrefixMax;

    impl_db_record!(
        key = TestKey2,
        value = TestVal2,
        db_prefix = TestDbKeyPrefix::MaxTest, // max/last prefix
        notify_on_modify = true,
    );
    impl_db_lookup!(key = TestKey2, query_prefix = DbPrefixTestPrefixMax);

    #[tokio::test(flavor = "multi_thread")]
    async fn test_retrieve_descending_order() {
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-descending-order")
            .tempdir()
            .unwrap();
        {
            let db = Database::new(
                RocksDb::open(&path).unwrap(),
                ModuleDecoderRegistry::default(),
            );
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(&TestKey(vec![0]), &TestVal(vec![3]))
                .await;
            dbtx.insert_entry(&TestKey(vec![254]), &TestVal(vec![1]))
                .await;
            dbtx.insert_entry(&TestKey(vec![255]), &TestVal(vec![2]))
                .await;
            dbtx.insert_entry(&TestKey2(vec![0]), &TestVal2(vec![3]))
                .await;
            dbtx.insert_entry(&TestKey2(vec![254]), &TestVal2(vec![1]))
                .await;
            dbtx.insert_entry(&TestKey2(vec![255]), &TestVal2(vec![2]))
                .await;
            let query = dbtx
                .find_by_prefix_sorted_descending(&DbPrefixTestPrefix)
                .await
                .collect::<Vec<_>>()
                .await;
            assert_eq!(
                query,
                vec![
                    (TestKey(vec![255]), TestVal(vec![2])),
                    (TestKey(vec![254]), TestVal(vec![1])),
                    (TestKey(vec![0]), TestVal(vec![3]))
                ]
            );
            let query = dbtx
                .find_by_prefix_sorted_descending(&DbPrefixTestPrefixMax)
                .await
                .collect::<Vec<_>>()
                .await;
            assert_eq!(
                query,
                vec![
                    (TestKey2(vec![255]), TestVal2(vec![2])),
                    (TestKey2(vec![254]), TestVal2(vec![1])),
                    (TestKey2(vec![0]), TestVal2(vec![3]))
                ]
            );
            dbtx.commit_tx().await;
        }
        // Test readonly implementation
        let db_readonly = RocksDbReadOnly::open_read_only(path).unwrap();
        let db_readonly = Database::new(db_readonly, Default::default());
        let mut dbtx = db_readonly.begin_transaction().await;
        let query = dbtx
            .find_by_prefix_sorted_descending(&DbPrefixTestPrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        assert_eq!(
            query,
            vec![
                (TestKey(vec![255]), TestVal(vec![2])),
                (TestKey(vec![254]), TestVal(vec![1])),
                (TestKey(vec![0]), TestVal(vec![3]))
            ]
        );
        let query = dbtx
            .find_by_prefix_sorted_descending(&DbPrefixTestPrefixMax)
            .await
            .collect::<Vec<_>>()
            .await;
        assert_eq!(
            query,
            vec![
                (TestKey2(vec![255]), TestVal2(vec![2])),
                (TestKey2(vec![254]), TestVal2(vec![1])),
                (TestKey2(vec![0]), TestVal2(vec![3]))
            ]
        );
    }
}
