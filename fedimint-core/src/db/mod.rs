//! Core Fedimint database traits and types
//!
//! This module provides the core key-value database for Fedimint.
//!
//! # Usage
//!
//! To use the database, you typically follow these steps:
//!
//! 1. Create a `Database` instance
//! 2. Begin a transaction
//! 3. Perform operations within the transaction
//! 4. Commit the transaction
//!
//! ## Example
//!
//! ```rust
//! use fedimint_core::db::mem_impl::MemDatabase;
//! use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
//! use fedimint_core::encoding::{Decodable, Encodable};
//! use fedimint_core::impl_db_record;
//! use fedimint_core::module::registry::ModuleDecoderRegistry;
//!
//! #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
//! pub struct TestKey(pub u64);
//! #[derive(Debug, Encodable, Decodable, Eq, PartialEq, PartialOrd, Ord)]
//! pub struct TestVal(pub u64);
//!
//! #[repr(u8)]
//! #[derive(Clone)]
//! pub enum TestDbKeyPrefix {
//!     Test = 0x42,
//! }
//!
//! impl_db_record!(
//!     key = TestKey,
//!     value = TestVal,
//!     db_prefix = TestDbKeyPrefix::Test,
//! );
//!
//! # async fn example() {
//! // Create a new in-memory database
//! let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
//!
//! // Begin a transaction
//! let mut tx = db.begin_transaction().await;
//!
//! // Perform operations
//! tx.insert_entry(&TestKey(1), &TestVal(100)).await;
//! let value = tx.get_value(&TestKey(1)).await;
//!
//! // Commit the transaction
//! tx.commit_tx().await;
//!
//! // For operations that may need to be retried due to conflicts, use the
//! // `autocommit` function:
//!
//! db.autocommit(
//!     |dbtx, _| {
//!         Box::pin(async move {
//!             dbtx.insert_entry(&TestKey(1), &TestVal(100)).await;
//!             anyhow::Ok(())
//!         })
//!     },
//!     None,
//! )
//! .await
//! .unwrap();
//! # }
//! ```
//!
//! # Isolation of database transactions
//!
//! Fedimint requires that the database implementation implement Snapshot
//! Isolation. Snapshot Isolation is a database isolation level that guarantees
//! consistent reads from the time that the snapshot was created (at transaction
//! creation time). Transactions with Snapshot Isolation level will only commit
//! if there has been no write to the modified keys since the snapshot (i.e.
//! write-write conflicts are prevented).
//!
//! Specifically, Fedimint expects the database implementation to prevent the
//! following anomalies:
//!
//! Non-Readable Write: TX1 writes (K1, V1) at time t but cannot read (K1, V1)
//! at time (t + i)
//!
//! Dirty Read: TX1 is able to read TX2's uncommitted writes.
//!
//! Non-Repeatable Read: TX1 reads (K1, V1) at time t and retrieves (K1, V2) at
//! time (t + i) where V1 != V2.
//!
//! Phantom Record: TX1 retrieves X number of records for a prefix at time t and
//! retrieves Y number of records for the same prefix at time (t + i).
//!
//! Lost Writes: TX1 writes (K1, V1) at the same time as TX2 writes (K1, V2). V2
//! overwrites V1 as the value for K1 (write-write conflict).
//!
//! | Type     | Non-Readable Write | Dirty Read | Non-Repeatable Read | Phantom
//! Record | Lost Writes | | -------- | ------------------ | ---------- |
//! ------------------- | -------------- | ----------- | | MemoryDB | Prevented
//! | Prevented  | Prevented           | Prevented      | Possible    |
//! | RocksDB  | Prevented          | Prevented  | Prevented           |
//! Prevented      | Prevented   | | Sqlite   | Prevented          | Prevented
//! | Prevented           | Prevented      | Prevented   |

use std::any;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug};
use std::marker::{self, PhantomData};
use std::ops::{self, DerefMut, Range};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hex::DisplayHex as _;
use fedimint_core::util::BoxFuture;
use fedimint_logging::LOG_DB;
use fedimint_util_error::FmtCompact as _;
use futures::{Stream, StreamExt};
use macro_rules_attribute::apply;
use rand::Rng;
use serde::Serialize;
use strum_macros::EnumIter;
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::core::{ModuleInstanceId, ModuleKind};
use crate::encoding::{Decodable, Encodable};
use crate::fmt_utils::AbbreviateHexBytes;
use crate::task::{MaybeSend, MaybeSync};
use crate::{async_trait_maybe_send, maybe_add_send, maybe_add_send_sync, timing};

pub mod mem_impl;
pub mod notifications;

pub use test_utils::*;

use self::notifications::{Notifications, NotifyQueue};
use crate::module::registry::{ModuleDecoderRegistry, ModuleRegistry};

pub const MODULE_GLOBAL_PREFIX: u8 = 0xff;

/// Result type for database operations
pub type DatabaseResult<T> = std::result::Result<T, DatabaseError>;

pub trait DatabaseKeyPrefix: Debug {
    fn to_bytes(&self) -> Vec<u8>;
}

/// A key + value pair in the database with a unique prefix
/// Extends `DatabaseKeyPrefix` to prepend the key's prefix.
pub trait DatabaseRecord: DatabaseKeyPrefix {
    const DB_PREFIX: u8;
    const NOTIFY_ON_MODIFY: bool = false;
    type Key: DatabaseKey + Debug;
    type Value: DatabaseValue + Debug;
}

/// A key that can be used to query one or more `DatabaseRecord`
/// Extends `DatabaseKeyPrefix` to prepend the key's prefix.
pub trait DatabaseLookup: DatabaseKeyPrefix {
    type Record: DatabaseRecord;
}

// Every `DatabaseRecord` is automatically a `DatabaseLookup`
impl<Record> DatabaseLookup for Record
where
    Record: DatabaseRecord + Debug + Decodable + Encodable,
{
    type Record = Record;
}

/// `DatabaseKey` that represents the lookup structure for retrieving key/value
/// pairs from the database.
pub trait DatabaseKey: Sized {
    /// Send a notification to tasks waiting to be notified if the value of
    /// `DatabaseKey` is modified
    ///
    /// For instance, this can be used to be notified when a key in the
    /// database is created. It is also possible to run a closure with the
    /// value of the `DatabaseKey` as parameter to verify some changes to
    /// that value.
    const NOTIFY_ON_MODIFY: bool = false;
    fn from_bytes(
        data: &[u8],
        modules: &ModuleDecoderRegistry,
    ) -> std::result::Result<Self, DecodingError>;
}

/// Marker trait for `DatabaseKey`s where `NOTIFY` is true
pub trait DatabaseKeyWithNotify {}

/// `DatabaseValue` that represents the value structure of database records.
pub trait DatabaseValue: Sized + Debug {
    fn from_bytes(
        data: &[u8],
        modules: &ModuleDecoderRegistry,
    ) -> std::result::Result<Self, DecodingError>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub type PrefixStream<'a> = Pin<Box<maybe_add_send!(dyn Stream<Item = (Vec<u8>, Vec<u8>)> + 'a)>>;

/// Just ignore this type, it's only there to make compiler happy
///
/// See <https://users.rust-lang.org/t/argument-requires-that-is-borrowed-for-static/66503/2?u=yandros> for details.
pub type PhantomBound<'big, 'small> = PhantomData<&'small &'big ()>;

/// Error returned when the autocommit function fails
#[derive(Debug, Error)]
pub enum AutocommitError<E> {
    /// Committing the transaction failed too many times, giving up
    #[error("Commit Failed: {last_error}")]
    CommitFailed {
        /// Number of attempts
        attempts: usize,
        /// Last error on commit
        last_error: DatabaseError,
    },
    /// Error returned by the closure provided to `autocommit`. If returned no
    /// commit was attempted in that round
    #[error("Closure error: {error}")]
    ClosureError {
        /// The attempt on which the closure returned an error
        ///
        /// Values other than 0 typically indicate a logic error since the
        /// closure given to `autocommit` should not have side effects
        /// and thus keep succeeding if it succeeded once.
        attempts: usize,
        /// Error returned by the closure
        error: E,
    },
}

pub trait AutocommitResultExt<T, E> {
    /// Unwraps the "commit failed" error variant. Use this in cases where
    /// autocommit is instructed to run indefinitely and commit will thus never
    /// fail.
    fn unwrap_autocommit(self) -> std::result::Result<T, E>;
}

impl<T, E> AutocommitResultExt<T, E> for std::result::Result<T, AutocommitError<E>> {
    fn unwrap_autocommit(self) -> std::result::Result<T, E> {
        match self {
            Ok(value) => Ok(value),
            Err(AutocommitError::CommitFailed { .. }) => {
                panic!("`unwrap_autocommit` called on a autocommit result with finite retries");
            }
            Err(AutocommitError::ClosureError { error, .. }) => Err(error),
        }
    }
}

/// Raw database implementation
///
/// This and [`IRawDatabaseTransaction`] are meant to be implemented
/// by crates like `fedimint-rocksdb` to provide a concrete implementation
/// of a database to be used by Fedimint.
///
/// This is in contrast of [`IDatabase`] which includes extra
/// functionality that Fedimint needs (and adds) on top of it.
#[apply(async_trait_maybe_send!)]
pub trait IRawDatabase: Debug + MaybeSend + MaybeSync + 'static {
    /// A raw database transaction type
    type Transaction<'a>: IRawDatabaseTransaction + Debug;

    /// Start a database transaction
    async fn begin_transaction<'a>(&'a self) -> Self::Transaction<'a>;

    // Checkpoint the database to a backup directory
    fn checkpoint(&self, backup_path: &Path) -> DatabaseResult<()>;
}

#[apply(async_trait_maybe_send!)]
impl<T> IRawDatabase for Box<T>
where
    T: IRawDatabase,
{
    type Transaction<'a> = <T as IRawDatabase>::Transaction<'a>;

    async fn begin_transaction<'a>(&'a self) -> Self::Transaction<'a> {
        (**self).begin_transaction().await
    }

    fn checkpoint(&self, backup_path: &Path) -> DatabaseResult<()> {
        (**self).checkpoint(backup_path)
    }
}

/// An extension trait with convenience operations on [`IRawDatabase`]
pub trait IRawDatabaseExt: IRawDatabase + Sized {
    /// Convert to type implementing [`IRawDatabase`] into [`Database`].
    ///
    /// When type inference is not an issue, [`Into::into`] can be used instead.
    fn into_database(self) -> Database {
        Database::new(self, ModuleRegistry::default())
    }
}

impl<T> IRawDatabaseExt for T where T: IRawDatabase {}

impl<T> From<T> for Database
where
    T: IRawDatabase,
{
    fn from(raw: T) -> Self {
        Self::new(raw, ModuleRegistry::default())
    }
}

/// A database that on top of a raw database operation, implements
/// key notification system.
#[apply(async_trait_maybe_send!)]
pub trait IDatabase: Debug + MaybeSend + MaybeSync + 'static {
    /// Start a database transaction
    async fn begin_transaction<'a>(&'a self) -> Box<dyn IDatabaseTransaction + 'a>;
    /// Register (and wait) for `key` updates
    async fn register(&self, key: &[u8]);
    /// Notify about `key` update (creation, modification, deletion)
    async fn notify(&self, key: &[u8]);

    /// The prefix len of this database refers to the global (as opposed to
    /// module-isolated) key space
    fn is_global(&self) -> bool;

    /// Checkpoints the database to a backup directory
    fn checkpoint(&self, backup_path: &Path) -> DatabaseResult<()>;
}

#[apply(async_trait_maybe_send!)]
impl<T> IDatabase for Arc<T>
where
    T: IDatabase + ?Sized,
{
    async fn begin_transaction<'a>(&'a self) -> Box<dyn IDatabaseTransaction + 'a> {
        (**self).begin_transaction().await
    }
    async fn register(&self, key: &[u8]) {
        (**self).register(key).await;
    }
    async fn notify(&self, key: &[u8]) {
        (**self).notify(key).await;
    }

    fn is_global(&self) -> bool {
        (**self).is_global()
    }

    fn checkpoint(&self, backup_path: &Path) -> DatabaseResult<()> {
        (**self).checkpoint(backup_path)
    }
}

/// Base functionality around [`IRawDatabase`] to make it a [`IDatabase`]
///
/// Mostly notification system, but also run-time single-commit handling.
struct BaseDatabase<RawDatabase> {
    notifications: Arc<Notifications>,
    raw: RawDatabase,
}

impl<RawDatabase> fmt::Debug for BaseDatabase<RawDatabase> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BaseDatabase")
    }
}

#[apply(async_trait_maybe_send!)]
impl<RawDatabase: IRawDatabase + MaybeSend + 'static> IDatabase for BaseDatabase<RawDatabase> {
    async fn begin_transaction<'a>(&'a self) -> Box<dyn IDatabaseTransaction + 'a> {
        Box::new(BaseDatabaseTransaction::new(
            self.raw.begin_transaction().await,
            self.notifications.clone(),
        ))
    }
    async fn register(&self, key: &[u8]) {
        self.notifications.register(key).await;
    }
    async fn notify(&self, key: &[u8]) {
        self.notifications.notify(key);
    }

    fn is_global(&self) -> bool {
        true
    }

    fn checkpoint(&self, backup_path: &Path) -> DatabaseResult<()> {
        self.raw.checkpoint(backup_path)
    }
}

/// A public-facing newtype over `IDatabase`
///
/// Notably carries set of module decoders (`ModuleDecoderRegistry`)
/// and implements common utility function for auto-commits, db isolation,
/// and other.
#[derive(Clone, Debug)]
pub struct Database {
    inner: Arc<dyn IDatabase + 'static>,
    module_decoders: ModuleDecoderRegistry,
}

impl Database {
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    pub fn into_inner(self) -> Arc<dyn IDatabase + 'static> {
        self.inner
    }
}

impl Database {
    /// Creates a new Fedimint database from any object implementing
    /// [`IDatabase`].
    ///
    /// See also [`Database::new_from_arc`].
    pub fn new(raw: impl IRawDatabase + 'static, module_decoders: ModuleDecoderRegistry) -> Self {
        let inner = BaseDatabase {
            raw,
            notifications: Arc::new(Notifications::new()),
        };
        Self::new_from_arc(
            Arc::new(inner) as Arc<dyn IDatabase + 'static>,
            module_decoders,
        )
    }

    /// Create [`Database`] from an already typed-erased `IDatabase`.
    pub fn new_from_arc(
        inner: Arc<dyn IDatabase + 'static>,
        module_decoders: ModuleDecoderRegistry,
    ) -> Self {
        Self {
            inner,
            module_decoders,
        }
    }

    /// Create [`Database`] isolated to a partition with a given `prefix`
    pub fn with_prefix(&self, prefix: Vec<u8>) -> Self {
        Self {
            inner: Arc::new(PrefixDatabase {
                inner: self.inner.clone(),
                global_dbtx_access_token: None,
                prefix,
            }),
            module_decoders: self.module_decoders.clone(),
        }
    }

    /// Create [`Database`] isolated to a partition with a prefix for a given
    /// `module_instance_id`, allowing the module to access `global_dbtx` with
    /// the right `access_token`
    pub fn with_prefix_module_id(
        &self,
        module_instance_id: ModuleInstanceId,
    ) -> (Self, GlobalDBTxAccessToken) {
        let prefix = module_instance_id_to_byte_prefix(module_instance_id);
        let global_dbtx_access_token = GlobalDBTxAccessToken::from_prefix(&prefix);
        (
            Self {
                inner: Arc::new(PrefixDatabase {
                    inner: self.inner.clone(),
                    global_dbtx_access_token: Some(global_dbtx_access_token),
                    prefix,
                }),
                module_decoders: self.module_decoders.clone(),
            },
            global_dbtx_access_token,
        )
    }

    pub fn with_decoders(&self, module_decoders: ModuleDecoderRegistry) -> Self {
        Self {
            inner: self.inner.clone(),
            module_decoders,
        }
    }

    /// Is this `Database` a global, unpartitioned `Database`
    pub fn is_global(&self) -> bool {
        self.inner.is_global()
    }

    /// `Err` if [`Self::is_global`] is not true
    pub fn ensure_global(&self) -> DatabaseResult<()> {
        if !self.is_global() {
            return Err(DatabaseError::Other(anyhow::anyhow!(
                "Database instance not global"
            )));
        }

        Ok(())
    }

    /// `Err` if [`Self::is_global`] is true
    pub fn ensure_isolated(&self) -> DatabaseResult<()> {
        if self.is_global() {
            return Err(DatabaseError::Other(anyhow::anyhow!(
                "Database instance not isolated"
            )));
        }

        Ok(())
    }

    /// Begin a new committable database transaction
    pub async fn begin_transaction<'s, 'tx>(&'s self) -> DatabaseTransaction<'tx, Committable>
    where
        's: 'tx,
    {
        DatabaseTransaction::<Committable>::new(
            self.inner.begin_transaction().await,
            self.module_decoders.clone(),
        )
    }

    /// Begin a new non-committable database transaction
    pub async fn begin_transaction_nc<'s, 'tx>(&'s self) -> DatabaseTransaction<'tx, NonCommittable>
    where
        's: 'tx,
    {
        self.begin_transaction().await.into_nc()
    }

    pub fn checkpoint(&self, backup_path: &Path) -> DatabaseResult<()> {
        self.inner.checkpoint(backup_path)
    }

    /// Runs a closure with a reference to a database transaction and tries to
    /// commit the transaction if the closure returns `Ok` and rolls it back
    /// otherwise. If committing fails the closure is run for up to
    /// `max_attempts` times. If `max_attempts` is `None` it will run
    /// `usize::MAX` times which is close enough to infinite times.
    ///
    /// The closure `tx_fn` provided should not have side effects outside of the
    /// database transaction provided, or if it does these should be
    /// idempotent, since the closure might be run multiple times.
    ///
    /// # Lifetime Parameters
    ///
    /// The higher rank trait bound (HRTB) `'a` that is applied to the the
    /// mutable reference to the database transaction ensures that the
    /// reference lives as least as long as the returned future of the
    /// closure.
    ///
    /// Further, the reference to self (`'s`) must outlive the
    /// `DatabaseTransaction<'dt>`. In other words, the
    /// `DatabaseTransaction` must live as least as long as `self` and that is
    /// true as the `DatabaseTransaction` is only dropped at the end of the
    /// `loop{}`.
    ///
    /// # Panics
    ///
    /// This function panics when the given number of maximum attempts is zero.
    /// `max_attempts` must be greater or equal to one.
    pub async fn autocommit<'s, 'dbtx, F, T, E>(
        &'s self,
        tx_fn: F,
        max_attempts: Option<usize>,
    ) -> std::result::Result<T, AutocommitError<E>>
    where
        's: 'dbtx,
        for<'r, 'o> F: Fn(
            &'r mut DatabaseTransaction<'o>,
            PhantomBound<'dbtx, 'o>,
        ) -> BoxFuture<'r, std::result::Result<T, E>>,
    {
        assert_ne!(max_attempts, Some(0));
        let mut curr_attempts: usize = 0;

        loop {
            // The `checked_add()` function is used to catch the `usize` overflow.
            // With `usize=32bit` and an assumed time of 1ms per iteration, this would crash
            // after ~50 days. But if that's the case, something else must be wrong.
            // With `usize=64bit` it would take much longer, obviously.
            curr_attempts = curr_attempts
                .checked_add(1)
                .expect("db autocommit attempt counter overflowed");

            let mut dbtx = self.begin_transaction().await;

            let tx_fn_res = tx_fn(&mut dbtx.to_ref_nc(), PhantomData).await;
            let val = match tx_fn_res {
                Ok(val) => val,
                Err(err) => {
                    dbtx.ignore_uncommitted();
                    return Err(AutocommitError::ClosureError {
                        attempts: curr_attempts,
                        error: err,
                    });
                }
            };

            let _timing /* logs on drop */ = timing::TimeReporter::new("autocommit - commit_tx");

            match dbtx.commit_tx_result().await {
                Ok(()) => {
                    return Ok(val);
                }
                Err(err) => {
                    if max_attempts.is_some_and(|max_att| max_att <= curr_attempts) {
                        warn!(
                            target: LOG_DB,
                            curr_attempts,
                            err = %err.fmt_compact(),
                            "Database commit failed in an autocommit block - terminating"
                        );
                        return Err(AutocommitError::CommitFailed {
                            attempts: curr_attempts,
                            last_error: err,
                        });
                    }

                    let delay = (2u64.pow(curr_attempts.min(7) as u32) * 10).min(1000);
                    let delay = rand::thread_rng().gen_range(delay..(2 * delay));
                    warn!(
                        target: LOG_DB,
                        curr_attempts,
                        err = %err.fmt_compact(),
                        delay_ms = %delay,
                        "Database commit failed in an autocommit block - retrying"
                    );
                    crate::runtime::sleep(Duration::from_millis(delay)).await;
                }
            }
        }
    }

    /// Waits for key to be notified.
    ///
    /// Calls the `checker` when value of the key may have changed.
    /// Returns the value when `checker` returns a `Some(T)`.
    pub async fn wait_key_check<'a, K, T>(
        &'a self,
        key: &K,
        checker: impl Fn(Option<K::Value>) -> Option<T>,
    ) -> (T, DatabaseTransaction<'a, Committable>)
    where
        K: DatabaseKey + DatabaseRecord + DatabaseKeyWithNotify,
    {
        let key_bytes = key.to_bytes();
        loop {
            // register for notification
            let notify = self.inner.register(&key_bytes);

            // check for value in db
            let mut tx = self.inner.begin_transaction().await;

            let maybe_value_bytes = tx
                .raw_get_bytes(&key_bytes)
                .await
                .expect("Unrecoverable error when reading from database")
                .map(|value_bytes| {
                    decode_value_expect(&value_bytes, &self.module_decoders, &key_bytes)
                });

            if let Some(value) = checker(maybe_value_bytes) {
                return (
                    value,
                    DatabaseTransaction::new(tx, self.module_decoders.clone()),
                );
            }

            // key not found, try again
            notify.await;
            // if miss a notification between await and next register, it is
            // fine. because we are going check the database
        }
    }

    /// Waits for key to be present in database.
    pub async fn wait_key_exists<K>(&self, key: &K) -> K::Value
    where
        K: DatabaseKey + DatabaseRecord + DatabaseKeyWithNotify,
    {
        self.wait_key_check(key, std::convert::identity).await.0
    }
}

fn module_instance_id_to_byte_prefix(module_instance_id: u16) -> Vec<u8> {
    let mut bytes = vec![MODULE_GLOBAL_PREFIX];
    bytes.append(&mut module_instance_id.consensus_encode_to_vec());
    bytes
}

/// A database that wraps an `inner` one and adds a prefix to all operations,
/// effectively creating an isolated partition.
#[derive(Clone, Debug)]
struct PrefixDatabase<Inner>
where
    Inner: Debug,
{
    prefix: Vec<u8>,
    global_dbtx_access_token: Option<GlobalDBTxAccessToken>,
    inner: Inner,
}

impl<Inner> PrefixDatabase<Inner>
where
    Inner: Debug,
{
    // TODO: we should optimize these concatenations, maybe by having an internal
    // `key: &[&[u8]]` that we flatten once, when passing to lowest layer, or
    // something
    fn get_full_key(&self, key: &[u8]) -> Vec<u8> {
        let mut full_key = self.prefix.clone();
        full_key.extend_from_slice(key);
        full_key
    }
}

#[apply(async_trait_maybe_send!)]
impl<Inner> IDatabase for PrefixDatabase<Inner>
where
    Inner: Debug + MaybeSend + MaybeSync + 'static + IDatabase,
{
    async fn begin_transaction<'a>(&'a self) -> Box<dyn IDatabaseTransaction + 'a> {
        Box::new(PrefixDatabaseTransaction {
            inner: self.inner.begin_transaction().await,
            global_dbtx_access_token: self.global_dbtx_access_token,
            prefix: self.prefix.clone(),
        })
    }
    async fn register(&self, key: &[u8]) {
        self.inner.register(&self.get_full_key(key)).await;
    }

    async fn notify(&self, key: &[u8]) {
        self.inner.notify(&self.get_full_key(key)).await;
    }

    fn is_global(&self) -> bool {
        if self.global_dbtx_access_token.is_some() {
            false
        } else {
            self.inner.is_global()
        }
    }

    fn checkpoint(&self, backup_path: &Path) -> DatabaseResult<()> {
        self.inner.checkpoint(backup_path)
    }
}

/// A database transactions that wraps an `inner` one and adds a prefix to all
/// operations, effectively creating an isolated partition.
///
/// Produced by [`PrefixDatabase`].
#[derive(Debug)]
struct PrefixDatabaseTransaction<Inner> {
    inner: Inner,
    global_dbtx_access_token: Option<GlobalDBTxAccessToken>,
    prefix: Vec<u8>,
}

impl<Inner> PrefixDatabaseTransaction<Inner> {
    // TODO: we should optimize these concatenations, maybe by having an internal
    // `key: &[&[u8]]` that we flatten once, when passing to lowest layer, or
    // something
    fn get_full_key(&self, key: &[u8]) -> Vec<u8> {
        let mut full_key = self.prefix.clone();
        full_key.extend_from_slice(key);
        full_key
    }

    fn get_full_range(&self, range: Range<&[u8]>) -> Range<Vec<u8>> {
        Range {
            start: self.get_full_key(range.start),
            end: self.get_full_key(range.end),
        }
    }

    fn adapt_prefix_stream(stream: PrefixStream<'_>, prefix_len: usize) -> PrefixStream<'_> {
        Box::pin(stream.map(move |(k, v)| (k[prefix_len..].to_owned(), v)))
    }
}

#[apply(async_trait_maybe_send!)]
impl<Inner> IDatabaseTransaction for PrefixDatabaseTransaction<Inner>
where
    Inner: IDatabaseTransaction,
{
    async fn commit_tx(&mut self) -> DatabaseResult<()> {
        self.inner.commit_tx().await
    }

    fn is_global(&self) -> bool {
        if self.global_dbtx_access_token.is_some() {
            false
        } else {
            self.inner.is_global()
        }
    }

    fn global_dbtx(
        &mut self,
        access_token: GlobalDBTxAccessToken,
    ) -> &mut dyn IDatabaseTransaction {
        if let Some(self_global_dbtx_access_token) = self.global_dbtx_access_token {
            assert_eq!(
                access_token, self_global_dbtx_access_token,
                "Invalid access key used to access global_dbtx"
            );
            &mut self.inner
        } else {
            self.inner.global_dbtx(access_token)
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl<Inner> IDatabaseTransactionOpsCore for PrefixDatabaseTransaction<Inner>
where
    Inner: IDatabaseTransactionOpsCore,
{
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>> {
        let key = self.get_full_key(key);
        self.inner.raw_insert_bytes(&key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        let key = self.get_full_key(key);
        self.inner.raw_get_bytes(&key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        let key = self.get_full_key(key);
        self.inner.raw_remove_entry(&key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        let key = self.get_full_key(key_prefix);
        let stream = self.inner.raw_find_by_prefix(&key).await?;
        Ok(Self::adapt_prefix_stream(stream, self.prefix.len()))
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        let key = self.get_full_key(key_prefix);
        let stream = self
            .inner
            .raw_find_by_prefix_sorted_descending(&key)
            .await?;
        Ok(Self::adapt_prefix_stream(stream, self.prefix.len()))
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>> {
        let range = self.get_full_range(range);
        let stream = self
            .inner
            .raw_find_by_range(Range {
                start: &range.start,
                end: &range.end,
            })
            .await?;
        Ok(Self::adapt_prefix_stream(stream, self.prefix.len()))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<()> {
        let key = self.get_full_key(key_prefix);
        self.inner.raw_remove_by_prefix(&key).await
    }
}

impl<Inner> IDatabaseTransactionOps for PrefixDatabaseTransaction<Inner> where
    Inner: IDatabaseTransactionOps
{
}

/// Core raw a operations database transactions supports
///
/// Used to enforce the same signature on all types supporting it
#[apply(async_trait_maybe_send!)]
pub trait IDatabaseTransactionOpsCore: MaybeSend {
    /// Insert entry
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>>;

    /// Get key value
    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>>;

    /// Remove entry by `key`
    async fn raw_remove_entry(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>>;

    /// Returns an stream of key-value pairs with keys that start with
    /// `key_prefix`, sorted by key.
    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>>;

    /// Same as [`Self::raw_find_by_prefix`] but the order is descending by key.
    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>>;

    /// Returns an stream of key-value pairs with keys within a `range`, sorted
    /// by key. [`Range`] is an (half-open) range bounded inclusively below and
    /// exclusively above.
    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>>;

    /// Delete keys matching prefix
    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<()>;
}

#[apply(async_trait_maybe_send!)]
impl<T> IDatabaseTransactionOpsCore for Box<T>
where
    T: IDatabaseTransactionOpsCore + ?Sized,
{
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>> {
        (**self).raw_insert_bytes(key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        (**self).raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        (**self).raw_remove_entry(key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        (**self).raw_find_by_prefix(key_prefix).await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        (**self)
            .raw_find_by_prefix_sorted_descending(key_prefix)
            .await
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>> {
        (**self).raw_find_by_range(range).await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<()> {
        (**self).raw_remove_by_prefix(key_prefix).await
    }
}

#[apply(async_trait_maybe_send!)]
impl<T> IDatabaseTransactionOpsCore for &mut T
where
    T: IDatabaseTransactionOpsCore + ?Sized,
{
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>> {
        (**self).raw_insert_bytes(key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        (**self).raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        (**self).raw_remove_entry(key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        (**self).raw_find_by_prefix(key_prefix).await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        (**self)
            .raw_find_by_prefix_sorted_descending(key_prefix)
            .await
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>> {
        (**self).raw_find_by_range(range).await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<()> {
        (**self).raw_remove_by_prefix(key_prefix).await
    }
}

/// Additional operations (only some) database transactions expose, on top of
/// [`IDatabaseTransactionOpsCore`]
///
/// In certain contexts exposing these operations would be a problem, so they
/// are moved to a separate trait.
pub trait IDatabaseTransactionOps: IDatabaseTransactionOpsCore + MaybeSend {}

impl<T> IDatabaseTransactionOps for Box<T> where T: IDatabaseTransactionOps + ?Sized {}

impl<T> IDatabaseTransactionOps for &mut T where T: IDatabaseTransactionOps + ?Sized {}

/// Like [`IDatabaseTransactionOpsCore`], but typed
///
/// Implemented via blanket impl for everything that implements
/// [`IDatabaseTransactionOpsCore`] that has decoders (implements
/// [`WithDecoders`]).
#[apply(async_trait_maybe_send!)]
pub trait IDatabaseTransactionOpsCoreTyped<'a> {
    async fn get_value<K>(&mut self, key: &K) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync;

    async fn insert_entry<K>(&mut self, key: &K, value: &K::Value) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
        K::Value: MaybeSend + MaybeSync;

    async fn insert_new_entry<K>(&mut self, key: &K, value: &K::Value)
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
        K::Value: MaybeSend + MaybeSync;

    async fn find_by_range<K>(
        &mut self,
        key_range: Range<K>,
    ) -> Pin<Box<maybe_add_send!(dyn Stream<Item = (K, K::Value)> + '_)>>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
        K::Value: MaybeSend + MaybeSync;

    async fn find_by_prefix<KP>(
        &mut self,
        key_prefix: &KP,
    ) -> Pin<
        Box<
            maybe_add_send!(
                dyn Stream<
                        Item = (
                            KP::Record,
                            <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value,
                        ),
                    > + '_
            ),
        >,
    >
    where
        KP: DatabaseLookup + MaybeSend + MaybeSync,
        KP::Record: DatabaseKey;

    async fn find_by_prefix_sorted_descending<KP>(
        &mut self,
        key_prefix: &KP,
    ) -> Pin<
        Box<
            maybe_add_send!(
                dyn Stream<
                        Item = (
                            KP::Record,
                            <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value,
                        ),
                    > + '_
            ),
        >,
    >
    where
        KP: DatabaseLookup + MaybeSend + MaybeSync,
        KP::Record: DatabaseKey;

    async fn remove_entry<K>(&mut self, key: &K) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync;

    async fn remove_by_prefix<KP>(&mut self, key_prefix: &KP)
    where
        KP: DatabaseLookup + MaybeSend + MaybeSync;
}

// blanket implementation of typed ops for anything that implements raw ops and
// has decoders
#[apply(async_trait_maybe_send!)]
impl<T> IDatabaseTransactionOpsCoreTyped<'_> for T
where
    T: IDatabaseTransactionOpsCore + WithDecoders,
{
    async fn get_value<K>(&mut self, key: &K) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
    {
        let key_bytes = key.to_bytes();
        let raw = self
            .raw_get_bytes(&key_bytes)
            .await
            .expect("Unrecoverable error occurred while reading and entry from the database");
        raw.map(|value_bytes| {
            decode_value_expect::<K::Value>(&value_bytes, self.decoders(), &key_bytes)
        })
    }

    async fn insert_entry<K>(&mut self, key: &K, value: &K::Value) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
        K::Value: MaybeSend + MaybeSync,
    {
        let key_bytes = key.to_bytes();
        self.raw_insert_bytes(&key_bytes, &value.to_bytes())
            .await
            .expect("Unrecoverable error occurred while inserting entry into the database")
            .map(|value_bytes| {
                decode_value_expect::<K::Value>(&value_bytes, self.decoders(), &key_bytes)
            })
    }

    async fn insert_new_entry<K>(&mut self, key: &K, value: &K::Value)
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
        K::Value: MaybeSend + MaybeSync,
    {
        if let Some(prev) = self.insert_entry(key, value).await {
            panic!(
                "Database overwriting element when expecting insertion of new entry. Key: {key:?} Prev Value: {prev:?}"
            );
        }
    }

    async fn find_by_range<K>(
        &mut self,
        key_range: Range<K>,
    ) -> Pin<Box<maybe_add_send!(dyn Stream<Item = (K, K::Value)> + '_)>>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
        K::Value: MaybeSend + MaybeSync,
    {
        let decoders = self.decoders().clone();
        Box::pin(
            self.raw_find_by_range(Range {
                start: &key_range.start.to_bytes(),
                end: &key_range.end.to_bytes(),
            })
            .await
            .expect("Unrecoverable error occurred while listing entries from the database")
            .map(move |(key_bytes, value_bytes)| {
                let key = decode_key_expect(&key_bytes, &decoders);
                let value = decode_value_expect(&value_bytes, &decoders, &key_bytes);
                (key, value)
            }),
        )
    }

    async fn find_by_prefix<KP>(
        &mut self,
        key_prefix: &KP,
    ) -> Pin<
        Box<
            maybe_add_send!(
                dyn Stream<
                        Item = (
                            KP::Record,
                            <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value,
                        ),
                    > + '_
            ),
        >,
    >
    where
        KP: DatabaseLookup + MaybeSend + MaybeSync,
        KP::Record: DatabaseKey,
    {
        let decoders = self.decoders().clone();
        Box::pin(
            self.raw_find_by_prefix(&key_prefix.to_bytes())
                .await
                .expect("Unrecoverable error occurred while listing entries from the database")
                .map(move |(key_bytes, value_bytes)| {
                    let key = decode_key_expect(&key_bytes, &decoders);
                    let value = decode_value_expect(&value_bytes, &decoders, &key_bytes);
                    (key, value)
                }),
        )
    }

    async fn find_by_prefix_sorted_descending<KP>(
        &mut self,
        key_prefix: &KP,
    ) -> Pin<
        Box<
            maybe_add_send!(
                dyn Stream<
                        Item = (
                            KP::Record,
                            <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value,
                        ),
                    > + '_
            ),
        >,
    >
    where
        KP: DatabaseLookup + MaybeSend + MaybeSync,
        KP::Record: DatabaseKey,
    {
        let decoders = self.decoders().clone();
        Box::pin(
            self.raw_find_by_prefix_sorted_descending(&key_prefix.to_bytes())
                .await
                .expect("Unrecoverable error occurred while listing entries from the database")
                .map(move |(key_bytes, value_bytes)| {
                    let key = decode_key_expect(&key_bytes, &decoders);
                    let value = decode_value_expect(&value_bytes, &decoders, &key_bytes);
                    (key, value)
                }),
        )
    }
    async fn remove_entry<K>(&mut self, key: &K) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
    {
        let key_bytes = key.to_bytes();
        self.raw_remove_entry(&key_bytes)
            .await
            .expect("Unrecoverable error occurred while inserting removing entry from the database")
            .map(|value_bytes| {
                decode_value_expect::<K::Value>(&value_bytes, self.decoders(), &key_bytes)
            })
    }
    async fn remove_by_prefix<KP>(&mut self, key_prefix: &KP)
    where
        KP: DatabaseLookup + MaybeSend + MaybeSync,
    {
        self.raw_remove_by_prefix(&key_prefix.to_bytes())
            .await
            .expect("Unrecoverable error when removing entries from the database");
    }
}

/// A database type that has decoders, which allows it to implement
/// [`IDatabaseTransactionOpsCoreTyped`]
pub trait WithDecoders {
    fn decoders(&self) -> &ModuleDecoderRegistry;
}

/// Raw database transaction (e.g. rocksdb implementation)
#[apply(async_trait_maybe_send!)]
pub trait IRawDatabaseTransaction: MaybeSend + IDatabaseTransactionOps {
    async fn commit_tx(self) -> DatabaseResult<()>;
}

/// Fedimint database transaction
///
/// See [`IDatabase`] for more info.
#[apply(async_trait_maybe_send!)]
pub trait IDatabaseTransaction: MaybeSend + IDatabaseTransactionOps + fmt::Debug {
    /// Commit the transaction
    async fn commit_tx(&mut self) -> DatabaseResult<()>;

    /// Is global database
    fn is_global(&self) -> bool;

    /// Get the global database tx from a module-prefixed database transaction
    ///
    /// Meant to be called only by core internals, and module developers should
    /// not call it directly.
    #[doc(hidden)]
    fn global_dbtx(&mut self, access_token: GlobalDBTxAccessToken)
    -> &mut dyn IDatabaseTransaction;
}

#[apply(async_trait_maybe_send!)]
impl<T> IDatabaseTransaction for Box<T>
where
    T: IDatabaseTransaction + ?Sized,
{
    async fn commit_tx(&mut self) -> DatabaseResult<()> {
        (**self).commit_tx().await
    }

    fn is_global(&self) -> bool {
        (**self).is_global()
    }

    fn global_dbtx(
        &mut self,
        access_token: GlobalDBTxAccessToken,
    ) -> &mut dyn IDatabaseTransaction {
        (**self).global_dbtx(access_token)
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a, T> IDatabaseTransaction for &'a mut T
where
    T: IDatabaseTransaction + ?Sized,
{
    async fn commit_tx(&mut self) -> DatabaseResult<()> {
        (**self).commit_tx().await
    }

    fn is_global(&self) -> bool {
        (**self).is_global()
    }

    fn global_dbtx(&mut self, access_key: GlobalDBTxAccessToken) -> &mut dyn IDatabaseTransaction {
        (**self).global_dbtx(access_key)
    }
}

/// Struct that implements `IRawDatabaseTransaction` and can be wrapped
/// easier in other structs since it does not consumed `self` by move.
struct BaseDatabaseTransaction<Tx> {
    // TODO: merge options
    raw: Option<Tx>,
    notify_queue: Option<NotifyQueue>,
    notifications: Arc<Notifications>,
}

impl<Tx> fmt::Debug for BaseDatabaseTransaction<Tx>
where
    Tx: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "BaseDatabaseTransaction{{ raw={:?} }}",
            self.raw
        ))
    }
}
impl<Tx> BaseDatabaseTransaction<Tx>
where
    Tx: IRawDatabaseTransaction,
{
    fn new(dbtx: Tx, notifications: Arc<Notifications>) -> Self {
        Self {
            raw: Some(dbtx),
            notifications,
            notify_queue: Some(NotifyQueue::new()),
        }
    }

    fn add_notification_key(&mut self, key: &[u8]) -> DatabaseResult<()> {
        self.notify_queue
            .as_mut()
            .ok_or(DatabaseError::TransactionConsumed)?
            .add(key);
        Ok(())
    }
}

#[apply(async_trait_maybe_send!)]
impl<Tx: IRawDatabaseTransaction> IDatabaseTransactionOpsCore for BaseDatabaseTransaction<Tx> {
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>> {
        self.add_notification_key(key)?;
        self.raw
            .as_mut()
            .ok_or(DatabaseError::TransactionConsumed)?
            .raw_insert_bytes(key, value)
            .await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        self.raw
            .as_mut()
            .ok_or(DatabaseError::TransactionConsumed)?
            .raw_get_bytes(key)
            .await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        self.add_notification_key(key)?;
        self.raw
            .as_mut()
            .ok_or(DatabaseError::TransactionConsumed)?
            .raw_remove_entry(key)
            .await
    }

    async fn raw_find_by_range(
        &mut self,
        key_range: Range<&[u8]>,
    ) -> DatabaseResult<PrefixStream<'_>> {
        self.raw
            .as_mut()
            .ok_or(DatabaseError::TransactionConsumed)?
            .raw_find_by_range(key_range)
            .await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        self.raw
            .as_mut()
            .ok_or(DatabaseError::TransactionConsumed)?
            .raw_find_by_prefix(key_prefix)
            .await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        self.raw
            .as_mut()
            .ok_or(DatabaseError::TransactionConsumed)?
            .raw_find_by_prefix_sorted_descending(key_prefix)
            .await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<()> {
        self.raw
            .as_mut()
            .ok_or(DatabaseError::TransactionConsumed)?
            .raw_remove_by_prefix(key_prefix)
            .await
    }
}

impl<Tx: IRawDatabaseTransaction> IDatabaseTransactionOps for BaseDatabaseTransaction<Tx> {}

#[apply(async_trait_maybe_send!)]
impl<Tx: IRawDatabaseTransaction + fmt::Debug> IDatabaseTransaction
    for BaseDatabaseTransaction<Tx>
{
    async fn commit_tx(&mut self) -> DatabaseResult<()> {
        self.raw
            .take()
            .ok_or(DatabaseError::TransactionConsumed)?
            .commit_tx()
            .await?;
        self.notifications.submit_queue(
            &self
                .notify_queue
                .take()
                .expect("commit must be called only once"),
        );
        Ok(())
    }

    fn is_global(&self) -> bool {
        true
    }

    fn global_dbtx(
        &mut self,
        _access_token: GlobalDBTxAccessToken,
    ) -> &mut dyn IDatabaseTransaction {
        panic!("Illegal to call global_dbtx on BaseDatabaseTransaction");
    }
}

/// A helper for tracking and logging on `Drop` any instances of uncommitted
/// writes
#[derive(Clone)]
struct CommitTracker {
    /// Is the dbtx committed
    is_committed: bool,
    /// Does the dbtx have any writes
    has_writes: bool,
    /// Don't warn-log uncommitted writes
    ignore_uncommitted: bool,
}

impl Drop for CommitTracker {
    fn drop(&mut self) {
        if self.has_writes && !self.is_committed {
            if self.ignore_uncommitted {
                trace!(
                    target: LOG_DB,
                    "DatabaseTransaction has writes and has not called commit, but that's expected."
                );
            } else {
                warn!(
                    target: LOG_DB,
                    location = ?backtrace::Backtrace::new(),
                    "DatabaseTransaction has writes and has not called commit."
                );
            }
        }
    }
}

enum MaybeRef<'a, T> {
    Owned(T),
    Borrowed(&'a mut T),
}

impl<T> ops::Deref for MaybeRef<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            MaybeRef::Owned(o) => o,
            MaybeRef::Borrowed(r) => r,
        }
    }
}

impl<T> ops::DerefMut for MaybeRef<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            MaybeRef::Owned(o) => o,
            MaybeRef::Borrowed(r) => r,
        }
    }
}

/// Session type for [`DatabaseTransaction`] that is allowed to commit
///
/// Opposite of [`NonCommittable`].
pub struct Committable;

/// Session type for a [`DatabaseTransaction`] that is not allowed to commit
///
/// Opposite of [`Committable`].
pub struct NonCommittable;

/// A high level database transaction handle
///
/// `Cap` is a session type
pub struct DatabaseTransaction<'tx, Cap = NonCommittable> {
    tx: Box<dyn IDatabaseTransaction + 'tx>,
    decoders: ModuleDecoderRegistry,
    commit_tracker: MaybeRef<'tx, CommitTracker>,
    on_commit_hooks: MaybeRef<'tx, Vec<Box<maybe_add_send!(dyn FnOnce())>>>,
    capability: marker::PhantomData<Cap>,
}

impl<Cap> fmt::Debug for DatabaseTransaction<'_, Cap> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "DatabaseTransaction {{ tx: {:?}, decoders={:?} }}",
            self.tx, self.decoders
        ))
    }
}

impl<Cap> WithDecoders for DatabaseTransaction<'_, Cap> {
    fn decoders(&self) -> &ModuleDecoderRegistry {
        &self.decoders
    }
}

#[instrument(target = LOG_DB, level = "trace", skip_all, fields(value_type = std::any::type_name::<V>()), err)]
fn decode_value<V: DatabaseValue>(
    value_bytes: &[u8],
    decoders: &ModuleDecoderRegistry,
) -> std::result::Result<V, DecodingError> {
    trace!(
        bytes = %AbbreviateHexBytes(value_bytes),
        "decoding value",
    );
    V::from_bytes(value_bytes, decoders)
}

#[track_caller]
fn decode_value_expect<V: DatabaseValue>(
    value_bytes: &[u8],
    decoders: &ModuleDecoderRegistry,
    key_bytes: &[u8],
) -> V {
    decode_value(value_bytes, decoders).unwrap_or_else(|err| {
        panic!(
            "Unrecoverable decoding DatabaseValue as {}; err={}, key_bytes={}, val_bytes={}",
            any::type_name::<V>(),
            err,
            AbbreviateHexBytes(key_bytes),
            AbbreviateHexBytes(value_bytes),
        )
    })
}

#[track_caller]
fn decode_key_expect<K: DatabaseKey>(key_bytes: &[u8], decoders: &ModuleDecoderRegistry) -> K {
    trace!(
        bytes = %AbbreviateHexBytes(key_bytes),
        "decoding key",
    );
    K::from_bytes(key_bytes, decoders).unwrap_or_else(|err| {
        panic!(
            "Unrecoverable decoding DatabaseKey as {}; err={}; bytes={}",
            any::type_name::<K>(),
            err,
            AbbreviateHexBytes(key_bytes)
        )
    })
}

impl<'tx, Cap> DatabaseTransaction<'tx, Cap> {
    /// Convert into a non-committable version
    pub fn into_nc(self) -> DatabaseTransaction<'tx, NonCommittable> {
        DatabaseTransaction {
            tx: self.tx,
            decoders: self.decoders,
            commit_tracker: self.commit_tracker,
            on_commit_hooks: self.on_commit_hooks,
            capability: PhantomData::<NonCommittable>,
        }
    }

    /// Get a reference to a non-committeable version
    pub fn to_ref_nc<'s, 'a>(&'s mut self) -> DatabaseTransaction<'a, NonCommittable>
    where
        's: 'a,
    {
        self.to_ref().into_nc()
    }

    /// Get [`DatabaseTransaction`] isolated to a `prefix`
    pub fn with_prefix<'a: 'tx>(self, prefix: Vec<u8>) -> DatabaseTransaction<'a, Cap>
    where
        'tx: 'a,
    {
        DatabaseTransaction {
            tx: Box::new(PrefixDatabaseTransaction {
                inner: self.tx,
                global_dbtx_access_token: None,
                prefix,
            }),
            decoders: self.decoders,
            commit_tracker: self.commit_tracker,
            on_commit_hooks: self.on_commit_hooks,
            capability: self.capability,
        }
    }

    /// Get [`DatabaseTransaction`] isolated to a prefix of a given
    /// `module_instance_id`, allowing the module to access global_dbtx
    /// with the right access token.
    pub fn with_prefix_module_id<'a: 'tx>(
        self,
        module_instance_id: ModuleInstanceId,
    ) -> (DatabaseTransaction<'a, Cap>, GlobalDBTxAccessToken)
    where
        'tx: 'a,
    {
        let prefix = module_instance_id_to_byte_prefix(module_instance_id);
        let global_dbtx_access_token = GlobalDBTxAccessToken::from_prefix(&prefix);
        (
            DatabaseTransaction {
                tx: Box::new(PrefixDatabaseTransaction {
                    inner: self.tx,
                    global_dbtx_access_token: Some(global_dbtx_access_token),
                    prefix,
                }),
                decoders: self.decoders,
                commit_tracker: self.commit_tracker,
                on_commit_hooks: self.on_commit_hooks,
                capability: self.capability,
            },
            global_dbtx_access_token,
        )
    }

    /// Get [`DatabaseTransaction`] to `self`
    pub fn to_ref<'s, 'a>(&'s mut self) -> DatabaseTransaction<'a, Cap>
    where
        's: 'a,
    {
        let decoders = self.decoders.clone();

        DatabaseTransaction {
            tx: Box::new(&mut self.tx),
            decoders,
            commit_tracker: match self.commit_tracker {
                MaybeRef::Owned(ref mut o) => MaybeRef::Borrowed(o),
                MaybeRef::Borrowed(ref mut b) => MaybeRef::Borrowed(b),
            },
            on_commit_hooks: match self.on_commit_hooks {
                MaybeRef::Owned(ref mut o) => MaybeRef::Borrowed(o),
                MaybeRef::Borrowed(ref mut b) => MaybeRef::Borrowed(b),
            },
            capability: self.capability,
        }
    }

    /// Get [`DatabaseTransaction`] isolated to a `prefix` of `self`
    pub fn to_ref_with_prefix<'a>(&'a mut self, prefix: Vec<u8>) -> DatabaseTransaction<'a, Cap>
    where
        'tx: 'a,
    {
        DatabaseTransaction {
            tx: Box::new(PrefixDatabaseTransaction {
                inner: &mut self.tx,
                global_dbtx_access_token: None,
                prefix,
            }),
            decoders: self.decoders.clone(),
            commit_tracker: match self.commit_tracker {
                MaybeRef::Owned(ref mut o) => MaybeRef::Borrowed(o),
                MaybeRef::Borrowed(ref mut b) => MaybeRef::Borrowed(b),
            },
            on_commit_hooks: match self.on_commit_hooks {
                MaybeRef::Owned(ref mut o) => MaybeRef::Borrowed(o),
                MaybeRef::Borrowed(ref mut b) => MaybeRef::Borrowed(b),
            },
            capability: self.capability,
        }
    }

    pub fn to_ref_with_prefix_module_id<'a>(
        &'a mut self,
        module_instance_id: ModuleInstanceId,
    ) -> (DatabaseTransaction<'a, Cap>, GlobalDBTxAccessToken)
    where
        'tx: 'a,
    {
        let prefix = module_instance_id_to_byte_prefix(module_instance_id);
        let global_dbtx_access_token = GlobalDBTxAccessToken::from_prefix(&prefix);
        (
            DatabaseTransaction {
                tx: Box::new(PrefixDatabaseTransaction {
                    inner: &mut self.tx,
                    global_dbtx_access_token: Some(global_dbtx_access_token),
                    prefix,
                }),
                decoders: self.decoders.clone(),
                commit_tracker: match self.commit_tracker {
                    MaybeRef::Owned(ref mut o) => MaybeRef::Borrowed(o),
                    MaybeRef::Borrowed(ref mut b) => MaybeRef::Borrowed(b),
                },
                on_commit_hooks: match self.on_commit_hooks {
                    MaybeRef::Owned(ref mut o) => MaybeRef::Borrowed(o),
                    MaybeRef::Borrowed(ref mut b) => MaybeRef::Borrowed(b),
                },
                capability: self.capability,
            },
            global_dbtx_access_token,
        )
    }

    /// Is this `Database` a global, unpartitioned `Database`
    pub fn is_global(&self) -> bool {
        self.tx.is_global()
    }

    /// `Err` if [`Self::is_global`] is not true
    pub fn ensure_global(&self) -> DatabaseResult<()> {
        if !self.is_global() {
            return Err(DatabaseError::Other(anyhow::anyhow!(
                "Database instance not global"
            )));
        }

        Ok(())
    }

    /// `Err` if [`Self::is_global`] is true
    pub fn ensure_isolated(&self) -> DatabaseResult<()> {
        if self.is_global() {
            return Err(DatabaseError::Other(anyhow::anyhow!(
                "Database instance not isolated"
            )));
        }

        Ok(())
    }

    /// Cancel the tx to avoid debugging warnings about uncommitted writes
    pub fn ignore_uncommitted(&mut self) -> &mut Self {
        self.commit_tracker.ignore_uncommitted = true;
        self
    }

    /// Create warnings about uncommitted writes
    pub fn warn_uncommitted(&mut self) -> &mut Self {
        self.commit_tracker.ignore_uncommitted = false;
        self
    }

    /// Register a hook that will be run after commit succeeds.
    #[instrument(target = LOG_DB, level = "trace", skip_all)]
    pub fn on_commit(&mut self, f: maybe_add_send!(impl FnOnce() + 'static)) {
        self.on_commit_hooks.push(Box::new(f));
    }

    pub fn global_dbtx<'a>(
        &'a mut self,
        access_token: GlobalDBTxAccessToken,
    ) -> DatabaseTransaction<'a, Cap>
    where
        'tx: 'a,
    {
        let decoders = self.decoders.clone();

        DatabaseTransaction {
            tx: Box::new(self.tx.global_dbtx(access_token)),
            decoders,
            commit_tracker: match self.commit_tracker {
                MaybeRef::Owned(ref mut o) => MaybeRef::Borrowed(o),
                MaybeRef::Borrowed(ref mut b) => MaybeRef::Borrowed(b),
            },
            on_commit_hooks: match self.on_commit_hooks {
                MaybeRef::Owned(ref mut o) => MaybeRef::Borrowed(o),
                MaybeRef::Borrowed(ref mut b) => MaybeRef::Borrowed(b),
            },
            capability: self.capability,
        }
    }
}

/// Code used to access `global_dbtx`
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GlobalDBTxAccessToken(u32);

impl GlobalDBTxAccessToken {
    /// Calculate an access code for accessing global_dbtx from a prefixed
    /// database tx
    ///
    /// Since we need to do it at runtime, we want the user modules not to be
    /// able to call `global_dbtx` too easily. But at the same time we don't
    /// need to be paranoid.
    ///
    /// This must be deterministic during whole instance of the software running
    /// (because it's being rederived independently in multiple codepahs) , but
    /// it could be somewhat randomized between different runs and releases.
    fn from_prefix(prefix: &[u8]) -> Self {
        Self(prefix.iter().fold(0, |acc, b| acc + u32::from(*b)) + 513)
    }
}

impl<'tx> DatabaseTransaction<'tx, Committable> {
    pub fn new(dbtx: Box<dyn IDatabaseTransaction + 'tx>, decoders: ModuleDecoderRegistry) -> Self {
        Self {
            tx: dbtx,
            decoders,
            commit_tracker: MaybeRef::Owned(CommitTracker {
                is_committed: false,
                has_writes: false,
                ignore_uncommitted: false,
            }),
            on_commit_hooks: MaybeRef::Owned(vec![]),
            capability: PhantomData,
        }
    }

    pub async fn commit_tx_result(mut self) -> DatabaseResult<()> {
        self.commit_tracker.is_committed = true;
        let commit_result = self.tx.commit_tx().await;

        // Run commit hooks in case commit was successful
        if commit_result.is_ok() {
            for hook in self.on_commit_hooks.deref_mut().drain(..) {
                hook();
            }
        }

        commit_result
    }

    pub async fn commit_tx(mut self) {
        self.commit_tracker.is_committed = true;
        self.commit_tx_result()
            .await
            .expect("Unrecoverable error occurred while committing to the database.");
    }
}

#[apply(async_trait_maybe_send!)]
impl<Cap> IDatabaseTransactionOpsCore for DatabaseTransaction<'_, Cap>
where
    Cap: Send,
{
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>> {
        self.commit_tracker.has_writes = true;
        self.tx.raw_insert_bytes(key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        self.tx.raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        self.tx.raw_remove_entry(key).await
    }

    async fn raw_find_by_range(
        &mut self,
        key_range: Range<&[u8]>,
    ) -> DatabaseResult<PrefixStream<'_>> {
        self.tx.raw_find_by_range(key_range).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        self.tx.raw_find_by_prefix(key_prefix).await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        self.tx
            .raw_find_by_prefix_sorted_descending(key_prefix)
            .await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> DatabaseResult<()> {
        self.commit_tracker.has_writes = true;
        self.tx.raw_remove_by_prefix(key_prefix).await
    }
}
impl IDatabaseTransactionOps for DatabaseTransaction<'_, Committable> {}

impl<T> DatabaseKeyPrefix for T
where
    T: DatabaseLookup + crate::encoding::Encodable + Debug,
{
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec![<Self as DatabaseLookup>::Record::DB_PREFIX];
        data.append(&mut self.consensus_encode_to_vec());
        data
    }
}

impl<T> DatabaseKey for T
where
    // Note: key can only be `T` that can be decoded without modules (even if
    // module type is `()`)
    T: DatabaseRecord + crate::encoding::Decodable + Sized,
{
    const NOTIFY_ON_MODIFY: bool = <T as DatabaseRecord>::NOTIFY_ON_MODIFY;
    fn from_bytes(
        data: &[u8],
        modules: &ModuleDecoderRegistry,
    ) -> std::result::Result<Self, DecodingError> {
        if data.is_empty() {
            // TODO: build better coding errors, pretty useless right now
            return Err(DecodingError::wrong_length(1, 0));
        }

        if data[0] != Self::DB_PREFIX {
            return Err(DecodingError::wrong_prefix(Self::DB_PREFIX, data[0]));
        }

        <Self as crate::encoding::Decodable>::consensus_decode_whole(&data[1..], modules)
            .map_err(|decode_error| DecodingError::Other(decode_error.0))
    }
}

impl<T> DatabaseValue for T
where
    T: Debug + Encodable + Decodable,
{
    fn from_bytes(
        data: &[u8],
        modules: &ModuleDecoderRegistry,
    ) -> std::result::Result<Self, DecodingError> {
        T::consensus_decode_whole(data, modules).map_err(|e| DecodingError::Other(e.0))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.consensus_encode_to_vec()
    }
}

/// This is a helper macro that generates the implementations of
/// `DatabaseRecord` necessary for reading/writing to the
/// database and fetching by prefix.
///
/// - `key`: This is the type of struct that will be used as the key into the
///   database
/// - `value`: This is the type of struct that will be used as the value into
///   the database
/// - `db_prefix`: Required enum expression that is represented as a `u8` and is
///   prepended to this key
/// - `query_prefix`: Optional type of struct that can be passed zero or more
///   times. Every query prefix can be used to query the database via
///   `find_by_prefix`
///
/// # Examples
///
/// ```
/// use fedimint_core::encoding::{Decodable, Encodable};
/// use fedimint_core::impl_db_record;
///
/// #[derive(Debug, Encodable, Decodable)]
/// struct MyKey;
///
/// #[derive(Debug, Encodable, Decodable)]
/// struct MyValue;
///
/// #[repr(u8)]
/// #[derive(Clone, Debug)]
/// pub enum DbKeyPrefix {
///     MyKey = 0x50,
/// }
///
/// impl_db_record!(key = MyKey, value = MyValue, db_prefix = DbKeyPrefix::MyKey);
/// ```
///
/// Use the required parameters and specify one `query_prefix`
///
/// ```
/// use fedimint_core::encoding::{Decodable, Encodable};
/// use fedimint_core::{impl_db_lookup, impl_db_record};
///
/// #[derive(Debug, Encodable, Decodable)]
/// struct MyKey;
///
/// #[derive(Debug, Encodable, Decodable)]
/// struct MyValue;
///
/// #[repr(u8)]
/// #[derive(Clone, Debug)]
/// pub enum DbKeyPrefix {
///     MyKey = 0x50,
/// }
///
/// #[derive(Debug, Encodable, Decodable)]
/// struct MyKeyPrefix;
///
/// impl_db_record!(key = MyKey, value = MyValue, db_prefix = DbKeyPrefix::MyKey,);
///
/// impl_db_lookup!(key = MyKey, query_prefix = MyKeyPrefix);
/// ```
#[macro_export]
macro_rules! impl_db_record {
    (key = $key:ty, value = $val:ty, db_prefix = $db_prefix:expr_2021 $(, notify_on_modify = $notify:tt)? $(,)?) => {
        impl $crate::db::DatabaseRecord for $key {
            const DB_PREFIX: u8 = $db_prefix as u8;
            $(const NOTIFY_ON_MODIFY: bool = $notify;)?
            type Key = Self;
            type Value = $val;
        }
        $(
            impl_db_record! {
                @impl_notify_marker key = $key, notify_on_modify = $notify
            }
        )?
    };
    // if notify is set to true
    (@impl_notify_marker key = $key:ty, notify_on_modify = true) => {
        impl $crate::db::DatabaseKeyWithNotify for $key {}
    };
    // if notify is set to false
    (@impl_notify_marker key = $key:ty, notify_on_modify = false) => {};
}

#[macro_export]
macro_rules! impl_db_lookup{
    (key = $key:ty $(, query_prefix = $query_prefix:ty)* $(,)?) => {
        $(
            impl $crate::db::DatabaseLookup for $query_prefix {
                type Record = $key;
            }
        )*
    };
}

/// Deprecated: Use `DatabaseVersionKey(ModuleInstanceId)` instead.
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct DatabaseVersionKeyV0;

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct DatabaseVersionKey(pub ModuleInstanceId);

#[derive(Debug, Encodable, Decodable, Serialize, Clone, PartialOrd, Ord, PartialEq, Eq, Copy)]
pub struct DatabaseVersion(pub u64);

impl_db_record!(
    key = DatabaseVersionKeyV0,
    value = DatabaseVersion,
    db_prefix = DbKeyPrefix::DatabaseVersion
);

impl_db_record!(
    key = DatabaseVersionKey,
    value = DatabaseVersion,
    db_prefix = DbKeyPrefix::DatabaseVersion
);

impl std::fmt::Display for DatabaseVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl DatabaseVersion {
    pub fn increment(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    DatabaseVersion = 0x50,
    ClientBackup = 0x51,
}

#[derive(Debug, Error)]
pub enum DecodingError {
    #[error("Key had a wrong prefix, expected {expected} but got {found}")]
    WrongPrefix { expected: u8, found: u8 },
    #[error("Key had a wrong length, expected {expected} but got {found}")]
    WrongLength { expected: usize, found: usize },
    #[error("Other decoding error: {0:#}")]
    Other(anyhow::Error),
}

impl DecodingError {
    pub fn other<E: Error + Send + Sync + 'static>(error: E) -> Self {
        Self::Other(anyhow::Error::from(error))
    }

    pub fn wrong_prefix(expected: u8, found: u8) -> Self {
        Self::WrongPrefix { expected, found }
    }

    pub fn wrong_length(expected: usize, found: usize) -> Self {
        Self::WrongLength { expected, found }
    }
}

/// Error type for database operations
#[derive(Debug, Error)]
pub enum DatabaseError {
    /// Write-write conflict during optimistic transaction commit.
    /// This occurs when two transactions attempt to modify the same key.
    #[error("Write-write conflict detected")]
    WriteConflict,

    /// The transaction has already been consumed (committed or dropped).
    /// Operations cannot be performed on a consumed transaction.
    #[error("Transaction already consumed")]
    TransactionConsumed,

    /// Error from the underlying database backend (e.g., RocksDB I/O errors).
    #[error("Database backend error: {0}")]
    DatabaseBackend(#[from] Box<dyn Error + Send + Sync>),

    /// Other database error
    #[error("Database error: {0:#}")]
    Other(anyhow::Error),
}

impl DatabaseError {
    /// Create a DatabaseError from any error type
    pub fn other<E: Error + Send + Sync + 'static>(error: E) -> Self {
        Self::Other(anyhow::Error::from(error))
    }

    /// Create a DatabaseBackend error from any error type
    pub fn backend<E: Error + Send + Sync + 'static>(error: E) -> Self {
        Self::DatabaseBackend(Box::new(error))
    }
}

impl From<anyhow::Error> for DatabaseError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(error)
    }
}

#[macro_export]
macro_rules! push_db_pair_items {
    ($dbtx:ident, $prefix_type:expr_2021, $key_type:ty, $value_type:ty, $map:ident, $key_literal:literal) => {
        let db_items =
            $crate::db::IDatabaseTransactionOpsCoreTyped::find_by_prefix($dbtx, &$prefix_type)
                .await
                .map(|(key, val)| {
                    (
                        $crate::encoding::Encodable::consensus_encode_to_hex(&key),
                        val,
                    )
                })
                .collect::<BTreeMap<String, $value_type>>()
                .await;

        $map.insert($key_literal.to_string(), Box::new(db_items));
    };
}

#[macro_export]
macro_rules! push_db_key_items {
    ($dbtx:ident, $prefix_type:expr_2021, $key_type:ty, $map:ident, $key_literal:literal) => {
        let db_items =
            $crate::db::IDatabaseTransactionOpsCoreTyped::find_by_prefix($dbtx, &$prefix_type)
                .await
                .map(|(key, _)| key)
                .collect::<Vec<$key_type>>()
                .await;

        $map.insert($key_literal.to_string(), Box::new(db_items));
    };
}

/// Context passed to the db migration _functions_ (pay attention to `Fn` in the
/// name)
///
/// Typically should not be referred to directly, and instead by a type-alias,
/// where the inner-context is set.
///
/// Notably it has the (optional) module id (inaccessible to the modules
/// directly, but used internally) and an inner context `C` injected by the
/// outer-layer.
///
/// `C` is generic, as in different layers / scopes (server vs client, etc.) a
/// different (module-typed, type erased, server/client, etc.) contexts might be
/// needed, while the database migration logic is kind of generic over that.
pub struct DbMigrationFnContext<'tx, C> {
    dbtx: DatabaseTransaction<'tx>,
    module_instance_id: Option<ModuleInstanceId>,
    ctx: C,
    __please_use_constructor: (),
}

impl<'tx, C> DbMigrationFnContext<'tx, C> {
    pub fn new(
        dbtx: DatabaseTransaction<'tx>,
        module_instance_id: Option<ModuleInstanceId>,
        ctx: C,
    ) -> Self {
        dbtx.ensure_global().expect("Must pass global dbtx");
        Self {
            dbtx,
            module_instance_id,
            ctx,
            // this is a constructor
            __please_use_constructor: (),
        }
    }

    pub fn map<R>(self, f: impl FnOnce(C) -> R) -> DbMigrationFnContext<'tx, R> {
        DbMigrationFnContext::new(self.dbtx, self.module_instance_id, f(self.ctx))
    }

    // TODO: this method is currently visible to the module itself, and it shouldn't
    #[doc(hidden)]
    pub fn split_dbtx_ctx<'s>(&'s mut self) -> (&'s mut DatabaseTransaction<'tx>, &'s C) {
        let Self { dbtx, ctx, .. } = self;

        (dbtx, ctx)
    }

    pub fn dbtx(&'_ mut self) -> DatabaseTransaction<'_> {
        if let Some(module_instance_id) = self.module_instance_id {
            self.dbtx.to_ref_with_prefix_module_id(module_instance_id).0
        } else {
            self.dbtx.to_ref_nc()
        }
    }

    // TODO: this method is currently visible to the module itself, and it shouldn't
    #[doc(hidden)]
    pub fn module_instance_id(&self) -> Option<ModuleInstanceId> {
        self.module_instance_id
    }
}

/// [`DbMigrationFn`] with no extra context (ATM gateway)
pub type GeneralDbMigrationFn = DbMigrationFn<()>;
pub type GeneralDbMigrationFnContext<'tx> = DbMigrationFnContext<'tx, ()>;

/// [`DbMigrationFn`] used by core client
///
/// NOTE: client _module_ migrations are handled using separate structs due to
/// state machine migrations
pub type ClientCoreDbMigrationFn = DbMigrationFn<()>;
pub type ClientCoreDbMigrationFnContext<'tx> = DbMigrationFnContext<'tx, ()>;

/// `CoreMigrationFn` that modules can implement to "migrate" the database
/// to the next database version.
///
/// It is parametrized over `C` (contents), which is extra data/type/interface
/// custom for different part of the codebase, e.g.:
///
/// * server core
/// * server modules
/// * client core
/// * gateway core
pub type DbMigrationFn<C> = Box<
    maybe_add_send_sync!(
        dyn for<'tx> Fn(
            DbMigrationFnContext<'tx, C>,
        ) -> Pin<
            Box<maybe_add_send!(dyn futures::Future<Output = anyhow::Result<()>> + 'tx)>,
        >
    ),
>;

/// Verifies that all database migrations are defined contiguously and returns
/// the "current" database version, which is one greater than the last key in
/// the map.
pub fn get_current_database_version<F>(
    migrations: &BTreeMap<DatabaseVersion, F>,
) -> DatabaseVersion {
    let versions = migrations.keys().copied().collect::<Vec<_>>();

    // Verify that all database migrations are defined contiguously. If there is a
    // gap, this indicates a programming error and we should panic.
    if !versions
        .windows(2)
        .all(|window| window[0].increment() == window[1])
    {
        panic!("Database Migrations are not defined contiguously");
    }

    versions
        .last()
        .map_or(DatabaseVersion(0), DatabaseVersion::increment)
}

pub async fn apply_migrations<C>(
    db: &Database,
    ctx: C,
    kind: String,
    migrations: BTreeMap<DatabaseVersion, DbMigrationFn<C>>,
    module_instance_id: Option<ModuleInstanceId>,
    // When used in client side context, we can/should ignore keys that external app
    // is allowed to use, and but since this function is shared, we make it optional argument
    external_prefixes_above: Option<u8>,
) -> std::result::Result<(), anyhow::Error>
where
    C: Clone,
{
    let mut dbtx = db.begin_transaction().await;
    apply_migrations_dbtx(
        &mut dbtx.to_ref_nc(),
        ctx,
        kind,
        migrations,
        module_instance_id,
        external_prefixes_above,
    )
    .await?;

    dbtx.commit_tx_result()
        .await
        .map_err(|e| anyhow::Error::msg(e.to_string()))
}
/// `apply_migrations` iterates from the on disk database version for the
/// module.
///
/// `apply_migrations` iterates from the on disk database version for the module
/// up to `target_db_version` and executes all of the migrations that exist in
/// the migrations map. Each migration in migrations map updates the
/// database to have the correct on-disk structures that the code is expecting.
/// The entire migration process is atomic (i.e migration from 0->1 and 1->2
/// happen atomically). This function is called before the module is initialized
/// and as long as the correct migrations are supplied in the migrations map,
/// the module will be able to read and write from the database successfully.
pub async fn apply_migrations_dbtx<C>(
    global_dbtx: &mut DatabaseTransaction<'_>,
    ctx: C,
    kind: String,
    migrations: BTreeMap<DatabaseVersion, DbMigrationFn<C>>,
    module_instance_id: Option<ModuleInstanceId>,
    // When used in client side context, we can/should ignore keys that external app
    // is allowed to use, and but since this function is shared, we make it optional argument
    external_prefixes_above: Option<u8>,
) -> std::result::Result<(), anyhow::Error>
where
    C: Clone,
{
    // Newly created databases will not have any data since they have just been
    // instantiated.
    let is_new_db = global_dbtx
        .raw_find_by_prefix(&[])
        .await?
        .filter(|(key, _v)| {
            std::future::ready(
                external_prefixes_above.is_none_or(|external_prefixes_above| {
                    !key.is_empty() && key[0] < external_prefixes_above
                }),
            )
        })
        .next()
        .await
        .is_none();

    let target_db_version = get_current_database_version(&migrations);

    // First write the database version to disk if it does not exist.
    create_database_version_dbtx(
        global_dbtx,
        target_db_version,
        module_instance_id,
        kind.clone(),
        is_new_db,
    )
    .await?;

    let module_instance_id_key = module_instance_id_or_global(module_instance_id);

    let disk_version = global_dbtx
        .get_value(&DatabaseVersionKey(module_instance_id_key))
        .await;

    let db_version = if let Some(disk_version) = disk_version {
        let mut current_db_version = disk_version;

        if current_db_version > target_db_version {
            return Err(anyhow::anyhow!(format!(
                "On disk database version {current_db_version} for module {kind} was higher than the code database version {target_db_version}."
            )));
        }

        while current_db_version < target_db_version {
            if let Some(migration) = migrations.get(&current_db_version) {
                info!(target: LOG_DB, ?kind, ?current_db_version, ?target_db_version, "Migrating module...");
                migration(DbMigrationFnContext::new(
                    global_dbtx.to_ref_nc(),
                    module_instance_id,
                    ctx.clone(),
                ))
                .await?;
            } else {
                warn!(target: LOG_DB, ?current_db_version, "Missing server db migration");
            }

            current_db_version = current_db_version.increment();

            global_dbtx
                .insert_entry(
                    &DatabaseVersionKey(module_instance_id_key),
                    &current_db_version,
                )
                .await;
        }

        current_db_version
    } else {
        target_db_version
    };

    debug!(target: LOG_DB, ?kind, ?db_version, "DB Version");
    Ok(())
}

pub async fn create_database_version(
    db: &Database,
    target_db_version: DatabaseVersion,
    module_instance_id: Option<ModuleInstanceId>,
    kind: String,
    is_new_db: bool,
) -> std::result::Result<(), anyhow::Error> {
    let mut dbtx = db.begin_transaction().await;

    create_database_version_dbtx(
        &mut dbtx.to_ref_nc(),
        target_db_version,
        module_instance_id,
        kind,
        is_new_db,
    )
    .await?;

    dbtx.commit_tx_result().await?;
    Ok(())
}

/// Creates the `DatabaseVersion` inside the database if it does not exist. If
/// necessary, this function will migrate the legacy database version to the
/// expected `DatabaseVersionKey`.
pub async fn create_database_version_dbtx(
    global_dbtx: &mut DatabaseTransaction<'_>,
    target_db_version: DatabaseVersion,
    module_instance_id: Option<ModuleInstanceId>,
    kind: String,
    is_new_db: bool,
) -> std::result::Result<(), anyhow::Error> {
    let key_module_instance_id = module_instance_id_or_global(module_instance_id);

    // First check if the module has a `DatabaseVersion` written to
    // `DatabaseVersionKey`. If `DatabaseVersion` already exists, there is
    // nothing to do.
    if global_dbtx
        .get_value(&DatabaseVersionKey(key_module_instance_id))
        .await
        .is_none()
    {
        // If it exists, read and remove the legacy `DatabaseVersion`, which used to be
        // in the module's isolated namespace (but not for fedimint-server or
        // fedimint-client).
        //
        // Otherwise, if the previous database contains data and no legacy database
        // version, use `DatabaseVersion(0)` so that all database migrations are
        // run. Otherwise, this database can assumed to be new and can use
        // `target_db_version` to skip the database migrations.
        let current_version_in_module = if let Some(module_instance_id) = module_instance_id {
            remove_current_db_version_if_exists(
                &mut global_dbtx
                    .to_ref_with_prefix_module_id(module_instance_id)
                    .0
                    .into_nc(),
                is_new_db,
                target_db_version,
            )
            .await
        } else {
            remove_current_db_version_if_exists(
                &mut global_dbtx.to_ref().into_nc(),
                is_new_db,
                target_db_version,
            )
            .await
        };

        // Write the previous `DatabaseVersion` to the new `DatabaseVersionKey`
        debug!(target: LOG_DB, ?kind, ?current_version_in_module, ?target_db_version, ?is_new_db, "Creating DatabaseVersionKey...");
        global_dbtx
            .insert_new_entry(
                &DatabaseVersionKey(key_module_instance_id),
                &current_version_in_module,
            )
            .await;
    }

    Ok(())
}

/// Removes `DatabaseVersion` from `DatabaseVersionKeyV0` if it exists and
/// returns the current database version. If the current version does not
/// exist, use `target_db_version` if the database is new. Otherwise, return
/// `DatabaseVersion(0)` to ensure all migrations are run.
async fn remove_current_db_version_if_exists(
    version_dbtx: &mut DatabaseTransaction<'_>,
    is_new_db: bool,
    target_db_version: DatabaseVersion,
) -> DatabaseVersion {
    // Remove the previous `DatabaseVersion` in the isolated database. If it doesn't
    // exist, just use the 0 for the version so that all of the migrations are
    // executed.
    let current_version_in_module = version_dbtx.remove_entry(&DatabaseVersionKeyV0).await;
    match current_version_in_module {
        Some(database_version) => database_version,
        None if is_new_db => target_db_version,
        None => DatabaseVersion(0),
    }
}

/// Helper function to retrieve the `module_instance_id` for modules, otherwise
/// return 0xff for the global namespace.
fn module_instance_id_or_global(module_instance_id: Option<ModuleInstanceId>) -> ModuleInstanceId {
    // Use 0xff for fedimint-server and the `module_instance_id` for each module
    module_instance_id.map_or_else(
        || MODULE_GLOBAL_PREFIX.into(),
        |module_instance_id| module_instance_id,
    )
}
#[allow(unused_imports)]
mod test_utils {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use fedimint_core::db::DbMigrationFnContext;
    use futures::future::ready;
    use futures::{Future, FutureExt, StreamExt};
    use rand::Rng;
    use tokio::join;

    use super::{
        Database, DatabaseTransaction, DatabaseVersion, DatabaseVersionKey, DatabaseVersionKeyV0,
        DbMigrationFn, apply_migrations,
    };
    use crate::core::ModuleKind;
    use crate::db::mem_impl::MemDatabase;
    use crate::db::{
        IDatabaseTransactionOps, IDatabaseTransactionOpsCoreTyped, MODULE_GLOBAL_PREFIX,
    };
    use crate::encoding::{Decodable, Encodable};
    use crate::module::registry::ModuleDecoderRegistry;

    pub async fn future_returns_shortly<F: Future>(fut: F) -> Option<F::Output> {
        crate::runtime::timeout(Duration::from_millis(10), fut)
            .await
            .ok()
    }

    #[repr(u8)]
    #[derive(Clone)]
    pub enum TestDbKeyPrefix {
        Test = 0x42,
        AltTest = 0x43,
        PercentTestKey = 0x25,
    }

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
    pub(super) struct TestKey(pub u64);

    #[derive(Debug, Encodable, Decodable)]
    struct DbPrefixTestPrefix;

    impl_db_record!(
        key = TestKey,
        value = TestVal,
        db_prefix = TestDbKeyPrefix::Test,
        notify_on_modify = true,
    );
    impl_db_lookup!(key = TestKey, query_prefix = DbPrefixTestPrefix);

    #[derive(Debug, Encodable, Decodable)]
    struct TestKeyV0(u64, u64);

    #[derive(Debug, Encodable, Decodable)]
    struct DbPrefixTestPrefixV0;

    impl_db_record!(
        key = TestKeyV0,
        value = TestVal,
        db_prefix = TestDbKeyPrefix::Test,
    );
    impl_db_lookup!(key = TestKeyV0, query_prefix = DbPrefixTestPrefixV0);

    #[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Encodable, Decodable)]
    struct AltTestKey(u64);

    #[derive(Debug, Encodable, Decodable)]
    struct AltDbPrefixTestPrefix;

    impl_db_record!(
        key = AltTestKey,
        value = TestVal,
        db_prefix = TestDbKeyPrefix::AltTest,
    );
    impl_db_lookup!(key = AltTestKey, query_prefix = AltDbPrefixTestPrefix);

    #[derive(Debug, Encodable, Decodable)]
    struct PercentTestKey(u64);

    #[derive(Debug, Encodable, Decodable)]
    struct PercentPrefixTestPrefix;

    impl_db_record!(
        key = PercentTestKey,
        value = TestVal,
        db_prefix = TestDbKeyPrefix::PercentTestKey,
    );

    impl_db_lookup!(key = PercentTestKey, query_prefix = PercentPrefixTestPrefix);
    #[derive(Debug, Encodable, Decodable, Eq, PartialEq, PartialOrd, Ord)]
    pub(super) struct TestVal(pub u64);

    const TEST_MODULE_PREFIX: u16 = 1;
    const ALT_MODULE_PREFIX: u16 = 2;

    pub async fn verify_insert_elements(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        assert!(dbtx.insert_entry(&TestKey(1), &TestVal(2)).await.is_none());
        assert!(dbtx.insert_entry(&TestKey(2), &TestVal(3)).await.is_none());
        dbtx.commit_tx().await;

        // Test values were persisted
        let mut dbtx = db.begin_transaction().await;
        assert_eq!(dbtx.get_value(&TestKey(1)).await, Some(TestVal(2)));
        assert_eq!(dbtx.get_value(&TestKey(2)).await, Some(TestVal(3)));
        dbtx.commit_tx().await;

        // Test overwrites work as expected
        let mut dbtx = db.begin_transaction().await;
        assert_eq!(
            dbtx.insert_entry(&TestKey(1), &TestVal(4)).await,
            Some(TestVal(2))
        );
        assert_eq!(
            dbtx.insert_entry(&TestKey(2), &TestVal(5)).await,
            Some(TestVal(3))
        );
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        assert_eq!(dbtx.get_value(&TestKey(1)).await, Some(TestVal(4)));
        assert_eq!(dbtx.get_value(&TestKey(2)).await, Some(TestVal(5)));
        dbtx.commit_tx().await;
    }

    pub async fn verify_remove_nonexisting(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        assert_eq!(dbtx.get_value(&TestKey(1)).await, None);
        let removed = dbtx.remove_entry(&TestKey(1)).await;
        assert!(removed.is_none());

        // Commit to suppress the warning message
        dbtx.commit_tx().await;
    }

    pub async fn verify_remove_existing(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        assert!(dbtx.insert_entry(&TestKey(1), &TestVal(2)).await.is_none());

        assert_eq!(dbtx.get_value(&TestKey(1)).await, Some(TestVal(2)));

        let removed = dbtx.remove_entry(&TestKey(1)).await;
        assert_eq!(removed, Some(TestVal(2)));
        assert_eq!(dbtx.get_value(&TestKey(1)).await, None);

        // Commit to suppress the warning message
        dbtx.commit_tx().await;
    }

    pub async fn verify_read_own_writes(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        assert!(dbtx.insert_entry(&TestKey(1), &TestVal(2)).await.is_none());

        assert_eq!(dbtx.get_value(&TestKey(1)).await, Some(TestVal(2)));

        // Commit to suppress the warning message
        dbtx.commit_tx().await;
    }

    pub async fn verify_prevent_dirty_reads(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        assert!(dbtx.insert_entry(&TestKey(1), &TestVal(2)).await.is_none());

        // dbtx2 should not be able to see uncommitted changes
        let mut dbtx2 = db.begin_transaction().await;
        assert_eq!(dbtx2.get_value(&TestKey(1)).await, None);

        // Commit to suppress the warning message
        dbtx.commit_tx().await;
    }

    pub async fn verify_find_by_range(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&TestKey(55), &TestVal(9999)).await;
        dbtx.insert_entry(&TestKey(54), &TestVal(8888)).await;
        dbtx.insert_entry(&TestKey(56), &TestVal(7777)).await;

        dbtx.insert_entry(&AltTestKey(55), &TestVal(7777)).await;
        dbtx.insert_entry(&AltTestKey(54), &TestVal(6666)).await;

        {
            let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(2).0;
            module_dbtx
                .insert_entry(&TestKey(300), &TestVal(3000))
                .await;
        }

        dbtx.commit_tx().await;

        // Verify finding by prefix returns the correct set of key pairs
        let mut dbtx = db.begin_transaction_nc().await;

        let returned_keys = dbtx
            .find_by_range(TestKey(55)..TestKey(56))
            .await
            .collect::<Vec<_>>()
            .await;

        let expected = vec![(TestKey(55), TestVal(9999))];

        assert_eq!(returned_keys, expected);

        let returned_keys = dbtx
            .find_by_range(TestKey(54)..TestKey(56))
            .await
            .collect::<Vec<_>>()
            .await;

        let expected = vec![(TestKey(54), TestVal(8888)), (TestKey(55), TestVal(9999))];
        assert_eq!(returned_keys, expected);

        let returned_keys = dbtx
            .find_by_range(TestKey(54)..TestKey(57))
            .await
            .collect::<Vec<_>>()
            .await;

        let expected = vec![
            (TestKey(54), TestVal(8888)),
            (TestKey(55), TestVal(9999)),
            (TestKey(56), TestVal(7777)),
        ];
        assert_eq!(returned_keys, expected);

        let mut module_dbtx = dbtx.with_prefix_module_id(2).0;
        let test_range = module_dbtx
            .find_by_range(TestKey(300)..TestKey(301))
            .await
            .collect::<Vec<_>>()
            .await;
        assert!(test_range.len() == 1);
    }

    pub async fn verify_find_by_prefix(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&TestKey(55), &TestVal(9999)).await;
        dbtx.insert_entry(&TestKey(54), &TestVal(8888)).await;

        dbtx.insert_entry(&AltTestKey(55), &TestVal(7777)).await;
        dbtx.insert_entry(&AltTestKey(54), &TestVal(6666)).await;
        dbtx.commit_tx().await;

        // Verify finding by prefix returns the correct set of key pairs
        let mut dbtx = db.begin_transaction().await;

        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .collect::<Vec<_>>()
            .await;

        let expected = vec![(TestKey(54), TestVal(8888)), (TestKey(55), TestVal(9999))];
        assert_eq!(returned_keys, expected);

        let reversed = dbtx
            .find_by_prefix_sorted_descending(&DbPrefixTestPrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        let mut reversed_expected = expected;
        reversed_expected.reverse();
        assert_eq!(reversed, reversed_expected);

        let returned_keys = dbtx
            .find_by_prefix(&AltDbPrefixTestPrefix)
            .await
            .collect::<Vec<_>>()
            .await;

        let expected = vec![
            (AltTestKey(54), TestVal(6666)),
            (AltTestKey(55), TestVal(7777)),
        ];
        assert_eq!(returned_keys, expected);

        let reversed = dbtx
            .find_by_prefix_sorted_descending(&AltDbPrefixTestPrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        let mut reversed_expected = expected;
        reversed_expected.reverse();
        assert_eq!(reversed, reversed_expected);
    }

    pub async fn verify_commit(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        assert!(dbtx.insert_entry(&TestKey(1), &TestVal(2)).await.is_none());
        dbtx.commit_tx().await;

        // Verify dbtx2 can see committed transactions
        let mut dbtx2 = db.begin_transaction().await;
        assert_eq!(dbtx2.get_value(&TestKey(1)).await, Some(TestVal(2)));
    }

    pub async fn verify_prevent_nonrepeatable_reads(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        assert_eq!(dbtx.get_value(&TestKey(100)).await, None);

        let mut dbtx2 = db.begin_transaction().await;

        dbtx2.insert_entry(&TestKey(100), &TestVal(101)).await;

        assert_eq!(dbtx.get_value(&TestKey(100)).await, None);

        dbtx2.commit_tx().await;

        // dbtx should still read None because it is operating over a snapshot
        // of the data when the transaction started
        assert_eq!(dbtx.get_value(&TestKey(100)).await, None);

        let expected_keys = 0;
        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, (key, value)| async move {
                if key == TestKey(100) {
                    assert!(value.eq(&TestVal(101)));
                }
                returned_keys + 1
            })
            .await;

        assert_eq!(returned_keys, expected_keys);
    }

    pub async fn verify_snapshot_isolation(db: Database) {
        async fn random_yield() {
            let times = if rand::thread_rng().gen_bool(0.5) {
                0
            } else {
                10
            };
            for _ in 0..times {
                tokio::task::yield_now().await;
            }
        }

        // This scenario is taken straight out of https://github.com/fedimint/fedimint/issues/5195 bug
        for i in 0..1000 {
            let base_key = i * 2;
            let tx_accepted_key = base_key;
            let spent_input_key = base_key + 1;

            join!(
                async {
                    random_yield().await;
                    let mut dbtx = db.begin_transaction().await;

                    random_yield().await;
                    let a = dbtx.get_value(&TestKey(tx_accepted_key)).await;
                    random_yield().await;
                    // we have 4 operations that can give you the db key,
                    // try all of them
                    let s = match i % 5 {
                        0 => dbtx.get_value(&TestKey(spent_input_key)).await,
                        1 => dbtx.remove_entry(&TestKey(spent_input_key)).await,
                        2 => {
                            dbtx.insert_entry(&TestKey(spent_input_key), &TestVal(200))
                                .await
                        }
                        3 => {
                            dbtx.find_by_prefix(&DbPrefixTestPrefix)
                                .await
                                .filter(|(k, _v)| ready(k == &TestKey(spent_input_key)))
                                .map(|(_k, v)| v)
                                .next()
                                .await
                        }
                        4 => {
                            dbtx.find_by_prefix_sorted_descending(&DbPrefixTestPrefix)
                                .await
                                .filter(|(k, _v)| ready(k == &TestKey(spent_input_key)))
                                .map(|(_k, v)| v)
                                .next()
                                .await
                        }
                        _ => {
                            panic!("woot?");
                        }
                    };

                    match (a, s) {
                        (None, None) | (Some(_), Some(_)) => {}
                        (None, Some(_)) => panic!("none some?! {i}"),
                        (Some(_), None) => panic!("some none?! {i}"),
                    }
                },
                async {
                    random_yield().await;

                    let mut dbtx = db.begin_transaction().await;
                    random_yield().await;
                    assert_eq!(dbtx.get_value(&TestKey(tx_accepted_key)).await, None);

                    random_yield().await;
                    assert_eq!(
                        dbtx.insert_entry(&TestKey(spent_input_key), &TestVal(100))
                            .await,
                        None
                    );

                    random_yield().await;
                    assert_eq!(
                        dbtx.insert_entry(&TestKey(tx_accepted_key), &TestVal(100))
                            .await,
                        None
                    );
                    random_yield().await;
                    dbtx.commit_tx().await;
                }
            );
        }
    }

    pub async fn verify_phantom_entry(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        dbtx.insert_entry(&TestKey(100), &TestVal(101)).await;

        dbtx.insert_entry(&TestKey(101), &TestVal(102)).await;

        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        let expected_keys = 2;
        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, (key, value)| async move {
                match key {
                    TestKey(100) => {
                        assert!(value.eq(&TestVal(101)));
                    }
                    TestKey(101) => {
                        assert!(value.eq(&TestVal(102)));
                    }
                    _ => {}
                }
                returned_keys + 1
            })
            .await;

        assert_eq!(returned_keys, expected_keys);

        let mut dbtx2 = db.begin_transaction().await;

        dbtx2.insert_entry(&TestKey(102), &TestVal(103)).await;

        dbtx2.commit_tx().await;

        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, (key, value)| async move {
                match key {
                    TestKey(100) => {
                        assert!(value.eq(&TestVal(101)));
                    }
                    TestKey(101) => {
                        assert!(value.eq(&TestVal(102)));
                    }
                    _ => {}
                }
                returned_keys + 1
            })
            .await;

        assert_eq!(returned_keys, expected_keys);
    }

    pub async fn expect_write_conflict(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&TestKey(100), &TestVal(101)).await;
        dbtx.commit_tx().await;

        let mut dbtx2 = db.begin_transaction().await;
        let mut dbtx3 = db.begin_transaction().await;

        dbtx2.insert_entry(&TestKey(100), &TestVal(102)).await;

        // Depending on if the database implementation supports optimistic or
        // pessimistic transactions, this test should generate an error here
        // (pessimistic) or at commit time (optimistic)
        dbtx3.insert_entry(&TestKey(100), &TestVal(103)).await;

        dbtx2.commit_tx().await;
        dbtx3.commit_tx_result().await.expect_err("Expecting an error to be returned because this transaction is in a write-write conflict with dbtx");
    }

    pub async fn verify_string_prefix(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&PercentTestKey(100), &TestVal(101)).await;

        assert_eq!(
            dbtx.get_value(&PercentTestKey(100)).await,
            Some(TestVal(101))
        );

        dbtx.insert_entry(&PercentTestKey(101), &TestVal(100)).await;

        dbtx.insert_entry(&PercentTestKey(101), &TestVal(100)).await;

        dbtx.insert_entry(&PercentTestKey(101), &TestVal(100)).await;

        // If the wildcard character ('%') is not handled properly, this will make
        // find_by_prefix return 5 results instead of 4
        dbtx.insert_entry(&TestKey(101), &TestVal(100)).await;

        let expected_keys = 4;
        let returned_keys = dbtx
            .find_by_prefix(&PercentPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, (key, value)| async move {
                if matches!(key, PercentTestKey(101)) {
                    assert!(value.eq(&TestVal(100)));
                }
                returned_keys + 1
            })
            .await;

        assert_eq!(returned_keys, expected_keys);
    }

    pub async fn verify_remove_by_prefix(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        dbtx.insert_entry(&TestKey(100), &TestVal(101)).await;

        dbtx.insert_entry(&TestKey(101), &TestVal(102)).await;

        dbtx.commit_tx().await;

        let mut remove_dbtx = db.begin_transaction().await;
        remove_dbtx.remove_by_prefix(&DbPrefixTestPrefix).await;
        remove_dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        let expected_keys = 0;
        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, (key, value)| async move {
                match key {
                    TestKey(100) => {
                        assert!(value.eq(&TestVal(101)));
                    }
                    TestKey(101) => {
                        assert!(value.eq(&TestVal(102)));
                    }
                    _ => {}
                }
                returned_keys + 1
            })
            .await;

        assert_eq!(returned_keys, expected_keys);
    }

    pub async fn verify_module_db(db: Database, module_db: Database) {
        let mut dbtx = db.begin_transaction().await;

        dbtx.insert_entry(&TestKey(100), &TestVal(101)).await;

        dbtx.insert_entry(&TestKey(101), &TestVal(102)).await;

        dbtx.commit_tx().await;

        // verify module_dbtx can only read key/value pairs from its own module
        let mut module_dbtx = module_db.begin_transaction().await;
        assert_eq!(module_dbtx.get_value(&TestKey(100)).await, None);

        assert_eq!(module_dbtx.get_value(&TestKey(101)).await, None);

        // verify module_dbtx can read key/value pairs that it wrote
        let mut dbtx = db.begin_transaction().await;
        assert_eq!(dbtx.get_value(&TestKey(100)).await, Some(TestVal(101)));

        assert_eq!(dbtx.get_value(&TestKey(101)).await, Some(TestVal(102)));

        let mut module_dbtx = module_db.begin_transaction().await;

        module_dbtx.insert_entry(&TestKey(100), &TestVal(103)).await;

        module_dbtx.insert_entry(&TestKey(101), &TestVal(104)).await;

        module_dbtx.commit_tx().await;

        let expected_keys = 2;
        let mut dbtx = db.begin_transaction().await;
        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, (key, value)| async move {
                match key {
                    TestKey(100) => {
                        assert!(value.eq(&TestVal(101)));
                    }
                    TestKey(101) => {
                        assert!(value.eq(&TestVal(102)));
                    }
                    _ => {}
                }
                returned_keys + 1
            })
            .await;

        assert_eq!(returned_keys, expected_keys);

        let removed = dbtx.remove_entry(&TestKey(100)).await;
        assert_eq!(removed, Some(TestVal(101)));
        assert_eq!(dbtx.get_value(&TestKey(100)).await, None);

        let mut module_dbtx = module_db.begin_transaction().await;
        assert_eq!(
            module_dbtx.get_value(&TestKey(100)).await,
            Some(TestVal(103))
        );
    }

    pub async fn verify_module_prefix(db: Database) {
        let mut test_dbtx = db.begin_transaction().await;
        {
            let mut test_module_dbtx = test_dbtx.to_ref_with_prefix_module_id(TEST_MODULE_PREFIX).0;

            test_module_dbtx
                .insert_entry(&TestKey(100), &TestVal(101))
                .await;

            test_module_dbtx
                .insert_entry(&TestKey(101), &TestVal(102))
                .await;
        }

        test_dbtx.commit_tx().await;

        let mut alt_dbtx = db.begin_transaction().await;
        {
            let mut alt_module_dbtx = alt_dbtx.to_ref_with_prefix_module_id(ALT_MODULE_PREFIX).0;

            alt_module_dbtx
                .insert_entry(&TestKey(100), &TestVal(103))
                .await;

            alt_module_dbtx
                .insert_entry(&TestKey(101), &TestVal(104))
                .await;
        }

        alt_dbtx.commit_tx().await;

        // verify test_module_dbtx can only see key/value pairs from its own module
        let mut test_dbtx = db.begin_transaction().await;
        let mut test_module_dbtx = test_dbtx.to_ref_with_prefix_module_id(TEST_MODULE_PREFIX).0;
        assert_eq!(
            test_module_dbtx.get_value(&TestKey(100)).await,
            Some(TestVal(101))
        );

        assert_eq!(
            test_module_dbtx.get_value(&TestKey(101)).await,
            Some(TestVal(102))
        );

        let expected_keys = 2;
        let returned_keys = test_module_dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, (key, value)| async move {
                match key {
                    TestKey(100) => {
                        assert!(value.eq(&TestVal(101)));
                    }
                    TestKey(101) => {
                        assert!(value.eq(&TestVal(102)));
                    }
                    _ => {}
                }
                returned_keys + 1
            })
            .await;

        assert_eq!(returned_keys, expected_keys);

        let removed = test_module_dbtx.remove_entry(&TestKey(100)).await;
        assert_eq!(removed, Some(TestVal(101)));
        assert_eq!(test_module_dbtx.get_value(&TestKey(100)).await, None);

        // test_dbtx on its own wont find the key because it does not use a module
        // prefix
        let mut test_dbtx = db.begin_transaction().await;
        assert_eq!(test_dbtx.get_value(&TestKey(101)).await, None);

        test_dbtx.commit_tx().await;
    }

    #[cfg(test)]
    #[tokio::test]
    pub async fn verify_test_migration() {
        // Insert a bunch of old dummy data that needs to be migrated to a new version
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let expected_test_keys_size: usize = 100;
        let mut dbtx = db.begin_transaction().await;
        for i in 0..expected_test_keys_size {
            dbtx.insert_new_entry(&TestKeyV0(i as u64, (i + 1) as u64), &TestVal(i as u64))
                .await;
        }

        // Will also be migrated to `DatabaseVersionKey`
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;
        dbtx.commit_tx().await;

        let mut migrations: BTreeMap<DatabaseVersion, DbMigrationFn<()>> = BTreeMap::new();

        migrations.insert(
            DatabaseVersion(0),
            Box::new(|ctx| migrate_test_db_version_0(ctx).boxed()),
        );

        apply_migrations(&db, (), "TestModule".to_string(), migrations, None, None)
            .await
            .expect("Error applying migrations for TestModule");

        // Verify that the migrations completed successfully
        let mut dbtx = db.begin_transaction().await;

        // Verify that the old `DatabaseVersion` under `DatabaseVersionKeyV0` migrated
        // to `DatabaseVersionKey`
        assert!(
            dbtx.get_value(&DatabaseVersionKey(MODULE_GLOBAL_PREFIX.into()))
                .await
                .is_some()
        );

        // Verify Dummy module migration
        let test_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        let test_keys_size = test_keys.len();
        assert_eq!(test_keys_size, expected_test_keys_size);
        for (key, val) in test_keys {
            assert_eq!(key.0, val.0 + 1);
        }
    }

    #[allow(dead_code)]
    async fn migrate_test_db_version_0(
        mut ctx: DbMigrationFnContext<'_, ()>,
    ) -> std::result::Result<(), anyhow::Error> {
        let mut dbtx = ctx.dbtx();
        let example_keys_v0 = dbtx
            .find_by_prefix(&DbPrefixTestPrefixV0)
            .await
            .collect::<Vec<_>>()
            .await;
        dbtx.remove_by_prefix(&DbPrefixTestPrefixV0).await;
        for (key, val) in example_keys_v0 {
            let key_v2 = TestKey(key.1);
            dbtx.insert_new_entry(&key_v2, &val).await;
        }
        Ok(())
    }

    #[cfg(test)]
    #[tokio::test]
    async fn test_autocommit() {
        use std::marker::PhantomData;
        use std::ops::Range;
        use std::path::Path;

        use anyhow::anyhow;
        use async_trait::async_trait;

        use crate::ModuleDecoderRegistry;
        use crate::db::{
            AutocommitError, BaseDatabaseTransaction, DatabaseError, DatabaseResult,
            IDatabaseTransaction, IDatabaseTransactionOps, IDatabaseTransactionOpsCore,
            IRawDatabase, IRawDatabaseTransaction,
        };

        #[derive(Debug)]
        struct FakeDatabase;

        #[async_trait]
        impl IRawDatabase for FakeDatabase {
            type Transaction<'a> = FakeTransaction<'a>;
            async fn begin_transaction(&self) -> FakeTransaction {
                FakeTransaction(PhantomData)
            }

            fn checkpoint(&self, _backup_path: &Path) -> DatabaseResult<()> {
                Ok(())
            }
        }

        #[derive(Debug)]
        struct FakeTransaction<'a>(PhantomData<&'a ()>);

        #[async_trait]
        impl IDatabaseTransactionOpsCore for FakeTransaction<'_> {
            async fn raw_insert_bytes(
                &mut self,
                _key: &[u8],
                _value: &[u8],
            ) -> DatabaseResult<Option<Vec<u8>>> {
                unimplemented!()
            }

            async fn raw_get_bytes(&mut self, _key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
                unimplemented!()
            }

            async fn raw_remove_entry(&mut self, _key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
                unimplemented!()
            }

            async fn raw_find_by_range(
                &mut self,
                _key_range: Range<&[u8]>,
            ) -> DatabaseResult<crate::db::PrefixStream<'_>> {
                unimplemented!()
            }

            async fn raw_find_by_prefix(
                &mut self,
                _key_prefix: &[u8],
            ) -> DatabaseResult<crate::db::PrefixStream<'_>> {
                unimplemented!()
            }

            async fn raw_remove_by_prefix(&mut self, _key_prefix: &[u8]) -> DatabaseResult<()> {
                unimplemented!()
            }

            async fn raw_find_by_prefix_sorted_descending(
                &mut self,
                _key_prefix: &[u8],
            ) -> DatabaseResult<crate::db::PrefixStream<'_>> {
                unimplemented!()
            }
        }

        impl IDatabaseTransactionOps for FakeTransaction<'_> {}

        #[async_trait]
        impl IRawDatabaseTransaction for FakeTransaction<'_> {
            async fn commit_tx(self) -> DatabaseResult<()> {
                use crate::db::DatabaseError;

                Err(DatabaseError::Other(anyhow::anyhow!("Can't commit!")))
            }
        }

        let db = Database::new(FakeDatabase, ModuleDecoderRegistry::default());
        let err = db
            .autocommit::<_, _, ()>(|_dbtx, _| Box::pin(async { Ok(()) }), Some(5))
            .await
            .unwrap_err();

        match err {
            AutocommitError::CommitFailed {
                attempts: failed_attempts,
                ..
            } => {
                assert_eq!(failed_attempts, 5);
            }
            AutocommitError::ClosureError { .. } => panic!("Closure did not return error"),
        }
    }
}

pub async fn find_by_prefix_sorted_descending<'r, 'inner, KP>(
    tx: &'r mut (dyn IDatabaseTransaction + 'inner),
    decoders: ModuleDecoderRegistry,
    key_prefix: &KP,
) -> impl Stream<
    Item = (
        KP::Record,
        <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value,
    ),
>
+ 'r
+ use<'r, KP>
where
    'inner: 'r,
    KP: DatabaseLookup,
    KP::Record: DatabaseKey,
{
    debug!(target: LOG_DB, "find by prefix sorted descending");
    let prefix_bytes = key_prefix.to_bytes();
    tx.raw_find_by_prefix_sorted_descending(&prefix_bytes)
        .await
        .expect("Error doing prefix search in database")
        .map(move |(key_bytes, value_bytes)| {
            let key = decode_key_expect(&key_bytes, &decoders);
            let value = decode_value_expect(&value_bytes, &decoders, &key_bytes);
            (key, value)
        })
}

pub async fn verify_module_db_integrity_dbtx(
    dbtx: &mut DatabaseTransaction<'_>,
    module_id: ModuleInstanceId,
    module_kind: ModuleKind,
    prefixes: &BTreeSet<u8>,
) {
    let module_db_prefix = module_instance_id_to_byte_prefix(module_id);
    if module_id < 250 {
        assert_eq!(module_db_prefix.len(), 2);
    }
    let mut records = dbtx
        .raw_find_by_prefix(&module_db_prefix)
        .await
        .expect("DB fail");
    while let Some((k, v)) = records.next().await {
        assert!(
            prefixes.contains(&k[module_db_prefix.len()]),
            "Unexpected module {module_kind} {module_id} db record found: {}: {}",
            k.as_hex(),
            v.as_hex()
        );
    }
}

#[cfg(test)]
mod tests;
