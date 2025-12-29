#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]

pub mod envs;

use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context as _, bail};
use async_trait::async_trait;
use fedimint_core::db::{
    DatabaseError, DatabaseResult, IDatabaseTransactionOps, IDatabaseTransactionOpsCore,
    IRawDatabase, IRawDatabaseTransaction, PrefixStream,
};
use fedimint_core::task::block_in_place;
use fedimint_db_locked::{Locked, LockedBuilder};
use futures::stream;
pub use rocksdb;
use rocksdb::{
    DBRecoveryMode, OptimisticTransactionDB, OptimisticTransactionOptions, WriteOptions,
};
use tracing::debug;

use crate::envs::FM_ROCKSDB_WRITE_BUFFER_SIZE_ENV;

// turn an `iter` into a `Stream` where every `next` is ran inside
// `block_in_place` to offload the blocking calls
fn convert_to_async_stream<'i, I>(iter: I) -> impl futures::Stream<Item = I::Item> + use<I>
where
    I: Iterator + Send + 'i,
    I::Item: Send,
{
    stream::unfold(iter, |mut iter| async {
        fedimint_core::runtime::block_in_place(|| {
            let item = iter.next();
            item.map(|item| (item, iter))
        })
    })
}

#[derive(Debug)]
pub struct RocksDb(rocksdb::OptimisticTransactionDB);

pub struct RocksDbTransaction<'a>(rocksdb::Transaction<'a, rocksdb::OptimisticTransactionDB>);

#[bon::bon]
impl RocksDb {
    /// Open the database using blocking IO
    #[builder(start_fn = build)]
    #[builder(finish_fn = open_blocking)]
    pub fn open_blocking(
        #[builder(start_fn)] db_path: impl AsRef<Path>,
        /// Relaxed consistency allows opening the database
        /// even if the wal got corrupted.
        relaxed_consistency: Option<bool>,
    ) -> anyhow::Result<Locked<RocksDb>> {
        let db_path = db_path.as_ref();

        block_in_place(|| {
            std::fs::create_dir_all(
                db_path
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("db path must have a base dir"))?,
            )?;
            LockedBuilder::new(db_path)?.with_db(|| {
                Self::open_blocking_unlocked(db_path, relaxed_consistency.unwrap_or_default())
            })
        })
    }
}

impl<I1, S> RocksDbOpenBlockingBuilder<I1, S>
where
    S: rocks_db_open_blocking_builder::State,
    I1: std::convert::AsRef<std::path::Path>,
{
    /// Open the database
    #[allow(clippy::unused_async)]
    pub async fn open(self) -> anyhow::Result<Locked<RocksDb>> {
        block_in_place(|| self.open_blocking())
    }
}

impl RocksDb {
    fn open_blocking_unlocked(
        db_path: &Path,
        relaxed_consistency: bool,
    ) -> anyhow::Result<RocksDb> {
        let mut opts = get_default_options()?;
        if relaxed_consistency {
            // https://github.com/fedimint/fedimint/issues/8072
            opts.set_wal_recovery_mode(DBRecoveryMode::TolerateCorruptedTailRecords);
        } else {
            // Since we turned synchronous writes one we should never encounter a corrupted
            // WAL and should rather fail in this case
            opts.set_wal_recovery_mode(DBRecoveryMode::AbsoluteConsistency);
        }
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::open(&opts, db_path)?;
        Ok(RocksDb(db))
    }

    pub fn inner(&self) -> &rocksdb::OptimisticTransactionDB {
        &self.0
    }
}

// TODO: Remove this and inline it in the places where it's used.
fn is_power_of_two(num: usize) -> bool {
    num.is_power_of_two()
}

impl fmt::Debug for RocksDbReadOnlyTransaction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RocksDbTransaction")
    }
}

impl fmt::Debug for RocksDbTransaction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RocksDbTransaction")
    }
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
    if let Ok(var) = std::env::var(FM_ROCKSDB_WRITE_BUFFER_SIZE_ENV) {
        debug!(var, "Using custom write buffer size");
        let size: usize = FromStr::from_str(&var)
            .with_context(|| format!("Could not parse {FM_ROCKSDB_WRITE_BUFFER_SIZE_ENV}"))?;
        if !is_power_of_two(size) {
            bail!("{} is not a power of 2", FM_ROCKSDB_WRITE_BUFFER_SIZE_ENV);
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
    #[allow(clippy::unused_async)]
    pub async fn open_read_only(db_path: impl AsRef<Path>) -> anyhow::Result<RocksDbReadOnly> {
        let db_path = db_path.as_ref();
        block_in_place(|| Self::open_read_only_blocking(db_path))
    }

    pub fn open_read_only_blocking(db_path: &Path) -> anyhow::Result<RocksDbReadOnly> {
        let opts = get_default_options()?;
        // Note: rocksdb is OK if one process has write access, and other read-access
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

        let mut write_options = WriteOptions::default();
        // Make sure we never lose data on unclean shutdown
        write_options.set_sync(true);

        RocksDbTransaction(self.0.transaction_opt(&write_options, &optimistic_options))
    }

    fn checkpoint(&self, backup_path: &Path) -> DatabaseResult<()> {
        let checkpoint =
            rocksdb::checkpoint::Checkpoint::new(&self.0).map_err(DatabaseError::backend)?;
        checkpoint
            .create_checkpoint(backup_path)
            .map_err(DatabaseError::backend)?;
        Ok(())
    }
}

#[async_trait]
impl IRawDatabase for RocksDbReadOnly {
    type Transaction<'a> = RocksDbReadOnlyTransaction<'a>;
    async fn begin_transaction<'a>(&'a self) -> RocksDbReadOnlyTransaction<'a> {
        RocksDbReadOnlyTransaction(&self.0)
    }

    fn checkpoint(&self, backup_path: &Path) -> DatabaseResult<()> {
        let checkpoint =
            rocksdb::checkpoint::Checkpoint::new(&self.0).map_err(DatabaseError::backend)?;
        checkpoint
            .create_checkpoint(backup_path)
            .map_err(DatabaseError::backend)?;
        Ok(())
    }
}

#[async_trait]
impl IDatabaseTransactionOpsCore for RocksDbTransaction<'_> {
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>> {
        fedimint_core::runtime::block_in_place(|| {
            let val = self.0.snapshot().get(key).unwrap();
            self.0.put(key, value).map_err(DatabaseError::backend)?;
            Ok(val)
        })
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        fedimint_core::runtime::block_in_place(|| {
            self.0.snapshot().get(key).map_err(DatabaseError::backend)
        })
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        fedimint_core::runtime::block_in_place(|| {
            let val = self.0.snapshot().get(key).unwrap();
            self.0.delete(key).map_err(DatabaseError::backend)?;
            Ok(val)
        })
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        Ok(fedimint_core::runtime::block_in_place(|| {
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

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>> {
        Ok(fedimint_core::runtime::block_in_place(|| {
            let range = Range {
                start: range.start.to_vec(),
                end: range.end.to_vec(),
            };
            let mut options = rocksdb::ReadOptions::default();
            options.set_iterate_range(range.clone());
            let iter = self.0.snapshot().iterator_opt(
                rocksdb::IteratorMode::From(&range.start, rocksdb::Direction::Forward),
                options,
            );
            let rocksdb_iter = iter.map_while(move |res| {
                let (key_bytes, value_bytes) = res.expect("Error reading from RocksDb");
                (key_bytes.as_ref() < range.end.as_slice())
                    .then_some((key_bytes.to_vec(), value_bytes.to_vec()))
            });
            Box::pin(convert_to_async_stream(rocksdb_iter))
        }))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<()> {
        fedimint_core::runtime::block_in_place(|| {
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
                .map_while(|res| {
                    res.map(|(key_bytes, _)| {
                        key_bytes
                            .starts_with(key_prefix)
                            .then_some(key_bytes.to_vec())
                    })
                    .transpose()
                });

            for item in iter {
                let key = item.map_err(DatabaseError::backend)?;
                self.0.delete(key).map_err(DatabaseError::backend)?;
            }

            Ok(())
        })
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        let prefix = key_prefix.to_vec();
        let next_prefix = next_prefix(&prefix);
        let iterator_mode = if let Some(next_prefix) = &next_prefix {
            rocksdb::IteratorMode::From(next_prefix, rocksdb::Direction::Reverse)
        } else {
            rocksdb::IteratorMode::End
        };
        Ok(fedimint_core::runtime::block_in_place(|| {
            let mut options = rocksdb::ReadOptions::default();
            options.set_iterate_range(rocksdb::PrefixRange(prefix.clone()));
            let iter = self.0.snapshot().iterator_opt(iterator_mode, options);
            let rocksdb_iter = iter.map_while(move |res| {
                let (key_bytes, value_bytes) = res.expect("Error reading from RocksDb");
                key_bytes
                    .starts_with(&prefix)
                    .then_some((key_bytes.to_vec(), value_bytes.to_vec()))
            });
            Box::pin(convert_to_async_stream(rocksdb_iter))
        }))
    }
}

impl IDatabaseTransactionOps for RocksDbTransaction<'_> {}

#[async_trait]
impl IRawDatabaseTransaction for RocksDbTransaction<'_> {
    async fn commit_tx(self) -> DatabaseResult<()> {
        fedimint_core::runtime::block_in_place(|| {
            match self.0.commit() {
                Ok(()) => Ok(()),
                Err(err) => {
                    // RocksDB's OptimisticTransactionDB can return Busy/TryAgain errors
                    // when concurrent transactions conflict on the same keys.
                    // These are retriable - return WriteConflict so autocommit retries.
                    // See: https://github.com/fedimint/fedimint/issues/8077
                    match err.kind() {
                        rocksdb::ErrorKind::Busy
                        | rocksdb::ErrorKind::TryAgain
                        | rocksdb::ErrorKind::MergeInProgress
                        | rocksdb::ErrorKind::TimedOut => Err(DatabaseError::WriteConflict),
                        _ => Err(DatabaseError::backend(err)),
                    }
                }
            }
        })
    }
}

#[async_trait]
impl IDatabaseTransactionOpsCore for RocksDbReadOnlyTransaction<'_> {
    async fn raw_insert_bytes(
        &mut self,
        _key: &[u8],
        _value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>> {
        panic!("Cannot insert into a read only transaction");
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        fedimint_core::runtime::block_in_place(|| {
            self.0.snapshot().get(key).map_err(DatabaseError::backend)
        })
    }

    async fn raw_remove_entry(&mut self, _key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        panic!("Cannot remove from a read only transaction");
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>> {
        Ok(fedimint_core::runtime::block_in_place(|| {
            let range = Range {
                start: range.start.to_vec(),
                end: range.end.to_vec(),
            };
            let mut options = rocksdb::ReadOptions::default();
            options.set_iterate_range(range.clone());
            let iter = self.0.snapshot().iterator_opt(
                rocksdb::IteratorMode::From(&range.start, rocksdb::Direction::Forward),
                options,
            );
            let rocksdb_iter = iter.map_while(move |res| {
                let (key_bytes, value_bytes) = res.expect("Error reading from RocksDb");
                (key_bytes.as_ref() < range.end.as_slice())
                    .then_some((key_bytes.to_vec(), value_bytes.to_vec()))
            });
            Box::pin(convert_to_async_stream(rocksdb_iter))
        }))
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        Ok(fedimint_core::runtime::block_in_place(|| {
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

    async fn raw_remove_by_prefix(&mut self, _key_prefix: &[u8]) -> DatabaseResult<()> {
        panic!("Cannot remove from a read only transaction");
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        let prefix = key_prefix.to_vec();
        let next_prefix = next_prefix(&prefix);
        let iterator_mode = if let Some(next_prefix) = &next_prefix {
            rocksdb::IteratorMode::From(next_prefix, rocksdb::Direction::Reverse)
        } else {
            rocksdb::IteratorMode::End
        };
        Ok(fedimint_core::runtime::block_in_place(|| {
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

impl IDatabaseTransactionOps for RocksDbReadOnlyTransaction<'_> {}

#[async_trait]
impl IRawDatabaseTransaction for RocksDbReadOnlyTransaction<'_> {
    async fn commit_tx(self) -> DatabaseResult<()> {
        panic!("Cannot commit a read only transaction");
    }
}

#[cfg(test)]
mod fedimint_rocksdb_tests {
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
    use fedimint_core::{impl_db_lookup, impl_db_record};
    use futures::StreamExt;

    use super::*;

    fn open_temp_db(temp_path: &str) -> Database {
        let path = tempfile::Builder::new()
            .prefix(temp_path)
            .tempdir()
            .unwrap();

        Database::new(
            RocksDb::build(path.as_ref()).open_blocking().unwrap(),
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
    async fn test_dbtx_find_by_range() {
        fedimint_core::db::verify_find_by_range(open_temp_db("fcb-rocksdb-test-find-by-range"))
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
    async fn test_dbtx_snapshot_isolation() {
        fedimint_core::db::verify_snapshot_isolation(open_temp_db(
            "fcb-rocksdb-test-snapshot-isolation",
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

    /// Test that concurrent transaction conflicts are handled gracefully
    /// with autocommit retry logic instead of panicking.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_transaction_conflict_with_autocommit() {
        use std::sync::Arc;

        let db = Arc::new(open_temp_db("fcb-rocksdb-test-concurrent-conflict"));

        // Spawn multiple concurrent tasks that all write to the same key
        // This will trigger optimistic transaction conflicts
        let mut handles = Vec::new();

        for i in 0u64..10 {
            let db_clone = Arc::clone(&db);
            let handle =
                fedimint_core::runtime::spawn("rocksdb-transient-error-test", async move {
                    for j in 0u64..10 {
                        // Use autocommit which handles retriable errors with retry logic
                        let result = db_clone
                            .autocommit::<_, _, anyhow::Error>(
                                |dbtx, _| {
                                    #[allow(clippy::cast_possible_truncation)]
                                    let val = (i * 100 + j) as u8;
                                    Box::pin(async move {
                                        // All transactions write to the same key to force conflicts
                                        dbtx.insert_entry(&TestKey(vec![0]), &TestVal(vec![val]))
                                            .await;
                                        Ok(())
                                    })
                                },
                                None, // unlimited retries
                            )
                            .await;

                        // Should succeed after retries, must NOT panic with "Resource busy"
                        assert!(
                            result.is_ok(),
                            "Transaction should succeed after retries, got: {result:?}",
                        );
                    }
                });
            handles.push(handle);
        }

        // Wait for all tasks - none should panic
        for handle in handles {
            handle.await.expect("Task should not panic");
        }
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
            RocksDb::build(path.as_ref()).open_blocking().unwrap(),
            ModuleDecoderRegistry::default(),
        );

        fedimint_core::db::verify_module_db(
            open_temp_db("fcb-rocksdb-test-module-db"),
            module_db.with_prefix_module_id(module_instance_id).0,
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
                RocksDb::build(&path).open().await.unwrap(),
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
        let db_readonly = RocksDbReadOnly::open_read_only(path).await.unwrap();
        let db_readonly = Database::new(db_readonly, ModuleRegistry::default());
        let mut dbtx = db_readonly.begin_transaction_nc().await;
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
