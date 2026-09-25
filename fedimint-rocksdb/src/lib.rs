#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]

pub mod envs;

use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::str::FromStr;

use async_trait::async_trait;
use fedimint_core::db::{
    DatabaseError, DatabaseResult, IDatabaseTransactionOps, IDatabaseTransactionOpsCore,
    IRawDatabase, IRawDatabaseTransaction, PrefixStream,
};
use fedimint_core::task::block_in_place;
use fedimint_db_locked::{DbLockError, Locked, LockedBuilder};
use futures::stream;
pub use rocksdb;
use rocksdb::{
    DBRecoveryMode, OptimisticTransactionDB, OptimisticTransactionOptions, WriteOptions,
};
use tracing::debug;

use crate::envs::{FM_ROCKSDB_BLOCK_CACHE_SIZE_ENV, FM_ROCKSDB_WRITE_BUFFER_SIZE_ENV};

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
    ) -> Result<Locked<RocksDb>, RocksDbOpenError> {
        let db_path = db_path.as_ref();

        block_in_place(|| {
            std::fs::create_dir_all(db_path.parent().ok_or(RocksDbOpenError::NoBaseDir)?)?;
            LockedBuilder::new(db_path)?.with_db(|| Self::open_blocking_unlocked(db_path))
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
    pub async fn open(self) -> Result<Locked<RocksDb>, RocksDbOpenError> {
        block_in_place(|| self.open_blocking())
    }
}

impl RocksDb {
    fn open_blocking_unlocked(db_path: &Path) -> Result<RocksDb, RocksDbOpenError> {
        let mut opts = get_default_options()?;
        // Synchronous writes (set_sync(true)) ensure completed writes are
        // durable, but a SIGKILL mid-write can still leave a truncated WAL tail
        // record. TolerateCorruptedTailRecords (RocksDB's own default) discards
        // only incomplete tail records — no committed data is lost.
        // AbsoluteConsistency was used previously but made the database
        // permanently unrecoverable after any unclean shutdown.
        // See: https://github.com/fedimint/fedimint/issues/8072
        opts.set_wal_recovery_mode(DBRecoveryMode::TolerateCorruptedTailRecords);
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

/// Default write buffer size: 2 MiB (`RocksDB` default is 64 MiB)
const DEFAULT_WRITE_BUFFER_SIZE: usize = 2 * 1024 * 1024;

/// Default block cache size: 2 MiB (`RocksDB` default is 8 MiB).
/// Index/filter blocks are placed in this cache too
/// (`set_cache_index_and_filter_blocks`), so everything is bounded.
/// We only need correctness, not throughput, so we keep this minimal.
const DEFAULT_BLOCK_CACHE_SIZE: usize = 2 * 1024 * 1024;

/// Default max open files: 256 (`RocksDB` default is unlimited which
/// consumes memory for each open file handle and associated metadata)
const DEFAULT_MAX_OPEN_FILES: i32 = 256;

fn parse_env_size(env_name: &'static str) -> Result<Option<usize>, RocksDbOpenError> {
    let Ok(var) = std::env::var(env_name) else {
        return Ok(None);
    };
    let size: usize = FromStr::from_str(&var).map_err(|source| RocksDbOpenError::EnvParse {
        var: env_name,
        source,
    })?;
    if !is_power_of_two(size) {
        return Err(RocksDbOpenError::EnvNotPowerOfTwo { var: env_name });
    }
    Ok(Some(size))
}

fn get_default_options() -> Result<rocksdb::Options, RocksDbOpenError> {
    let mut opts = rocksdb::Options::default();

    let write_buffer_size =
        parse_env_size(FM_ROCKSDB_WRITE_BUFFER_SIZE_ENV)?.unwrap_or(DEFAULT_WRITE_BUFFER_SIZE);
    opts.set_write_buffer_size(write_buffer_size);

    // Keep at most 2 write buffers (1 active + 1 flushing)
    opts.set_max_write_buffer_number(2);

    let block_cache_size =
        parse_env_size(FM_ROCKSDB_BLOCK_CACHE_SIZE_ENV)?.unwrap_or(DEFAULT_BLOCK_CACHE_SIZE);
    let cache = rocksdb::Cache::new_lru_cache(block_cache_size);
    let mut block_opts = rocksdb::BlockBasedOptions::default();
    block_opts.set_block_cache(&cache);
    // Put index and filter blocks into the block cache so they are
    // bounded by the same memory budget instead of growing unbounded.
    block_opts.set_cache_index_and_filter_blocks(true);
    opts.set_block_based_table_factory(&block_opts);

    opts.set_max_open_files(DEFAULT_MAX_OPEN_FILES);

    debug!(
        write_buffer_size,
        block_cache_size,
        max_open_files = DEFAULT_MAX_OPEN_FILES,
        "RocksDB memory options"
    );

    opts.create_if_missing(true);
    Ok(opts)
}

#[derive(Debug)]
pub struct RocksDbReadOnly(rocksdb::DB);

pub struct RocksDbReadOnlyTransaction<'a>(&'a rocksdb::DB);

impl RocksDbReadOnly {
    #[allow(clippy::unused_async)]
    pub async fn open_read_only(
        db_path: impl AsRef<Path>,
    ) -> Result<RocksDbReadOnly, RocksDbOpenError> {
        let db_path = db_path.as_ref();
        block_in_place(|| Self::open_read_only_blocking(db_path))
    }

    pub fn open_read_only_blocking(db_path: &Path) -> Result<RocksDbReadOnly, RocksDbOpenError> {
        let opts = get_default_options()?;
        // Note: rocksdb is OK if one process has write access, and other read-access
        let db = rocksdb::DB::open_for_read_only(&opts, db_path, false)?;
        Ok(RocksDbReadOnly(db))
    }
}

/// Why a [`RocksDb`] or [`RocksDbReadOnly`] could not be opened.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RocksDbOpenError {
    /// The database path has no parent directory to create; only when
    /// opening for writing.
    #[error("db path must have a base dir")]
    NoBaseDir,

    /// The parent directory of the database could not be created; only when
    /// opening for writing.
    #[error(transparent)]
    CreateDir(#[from] std::io::Error),

    /// The lock file next to the database could not be opened or locked;
    /// only when opening for writing.
    #[error(transparent)]
    Lock(#[from] DbLockError),

    /// A size override in the environment is not a number.
    #[error("Could not parse {var}")]
    EnvParse {
        /// The environment variable.
        var: &'static str,
        /// Why its value is not a number.
        #[source]
        source: std::num::ParseIntError,
    },

    /// A size override in the environment is not a power of two.
    #[error("{var} is not a power of 2")]
    EnvNotPowerOfTwo {
        /// The environment variable.
        var: &'static str,
    },

    /// `RocksDB` could not open the database.
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),
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
                    // `Busy` means another transaction wrote a key this one also wrote,
                    // after our snapshot was taken. `TryAgain` means RocksDB could not
                    // check for conflicts at all, because our snapshot is older than the
                    // write history it retains — a different failure with a different
                    // fix, so it gets its own variant.
                    //
                    // Anything else keeps its original kind and message: collapsing
                    // unrelated failures into a conflict hides what actually went wrong.
                    // Note that `Database::autocommit` retries on any commit error, so
                    // nothing here changes which errors it recovers from.
                    //
                    // See: https://github.com/fedimint/fedimint/issues/8077
                    // See: https://github.com/fedimint/fedimint/issues/8872
                    match err.kind() {
                        rocksdb::ErrorKind::Busy => Err(DatabaseError::WriteConflict),
                        rocksdb::ErrorKind::TryAgain => Err(DatabaseError::snapshot_too_old(err)),
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
mod fedimint_rocksdb_tests;
