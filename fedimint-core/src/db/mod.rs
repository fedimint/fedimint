//! Core Fedimint database traits and types
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

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Debug};
use std::marker::{self, PhantomData};
use std::ops::{self, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use fedimint_core::util::BoxFuture;
use fedimint_logging::LOG_DB;
use futures::{Stream, StreamExt};
use macro_rules_attribute::apply;
use rand::Rng;
use serde::Serialize;
use strum_macros::EnumIter;
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::core::ModuleInstanceId;
use crate::encoding::{Decodable, Encodable};
use crate::fmt_utils::AbbreviateHexBytes;
use crate::task::{MaybeSend, MaybeSync};
use crate::{async_trait_maybe_send, maybe_add_send, timing};

pub mod mem_impl;
pub mod notifications;

pub use test_utils::*;

use self::notifications::{Notifications, NotifyQueue};
use crate::module::registry::ModuleDecoderRegistry;

pub const MODULE_GLOBAL_PREFIX: u8 = 0xff;

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
    fn from_bytes(data: &[u8], modules: &ModuleDecoderRegistry) -> Result<Self, DecodingError>;
}

/// Marker trait for `DatabaseKey`s where `NOTIFY` is true
pub trait DatabaseKeyWithNotify {}

/// `DatabaseValue` that represents the value structure of database records.
pub trait DatabaseValue: Sized + Debug {
    fn from_bytes(data: &[u8], modules: &ModuleDecoderRegistry) -> Result<Self, DecodingError>;
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
    CommitFailed {
        /// Number of attempts
        attempts: usize,
        /// Last error on commit
        last_error: anyhow::Error,
    },
    /// Error returned by the closure provided to `autocommit`. If returned no
    /// commit was attempted in that round
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
    type Transaction<'a>: IRawDatabaseTransaction;

    /// Start a database transaction
    async fn begin_transaction<'a>(&'a self) -> Self::Transaction<'a>;
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
}

/// An extension trait with convenience operations on [`IRawDatabase`]
pub trait IRawDatabaseExt: IRawDatabase + Sized {
    /// Convert to type implementing [`IRawDatabase`] into [`Database`].
    ///
    /// When type inference is not an issue, [`Into::into`] can be used instead.
    fn into_database(self) -> Database {
        Database::new(self, Default::default())
    }
}

impl<T> IRawDatabaseExt for T where T: IRawDatabase {}

impl<T> From<T> for Database
where
    T: IRawDatabase,
{
    fn from(raw: T) -> Self {
        Database::new(raw, Default::default())
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

    /// The prefix len of this database instance
    fn prefix_len(&self) -> usize;
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
        (**self).register(key).await
    }
    async fn notify(&self, key: &[u8]) {
        (**self).notify(key).await
    }

    fn prefix_len(&self) -> usize {
        (**self).prefix_len()
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
        self.notifications.register(key).await
    }
    async fn notify(&self, key: &[u8]) {
        self.notifications.notify(key).await
    }

    fn prefix_len(&self) -> usize {
        0
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
                prefix,
            }),
            module_decoders: self.module_decoders.clone(),
        }
    }

    /// Create [`Database`] isolated to a partition with a prefix for a given
    /// `module_instance_id`
    pub fn with_prefix_module_id(&self, module_instance_id: ModuleInstanceId) -> Self {
        let prefix = module_instance_id_to_byte_prefix(module_instance_id);
        self.with_prefix(prefix)
    }

    pub fn with_decoders(&self, module_decoders: ModuleDecoderRegistry) -> Self {
        Self {
            inner: self.inner.clone(),
            module_decoders,
        }
    }

    /// Is this `Database` a global, unpartitioned `Database`
    pub fn is_global(&self) -> bool {
        self.inner.prefix_len() == 0
    }

    /// `Err` if [`Self::is_global`] is not true
    pub fn ensure_global(&self) -> Result<()> {
        if !self.is_global() {
            bail!("Database instance not global");
        }

        Ok(())
    }

    /// `Err` if [`Self::is_global`] is true
    pub fn ensure_isolated(&self) -> Result<()> {
        if self.is_global() {
            bail!("Database instance not isolated");
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
    ) -> Result<T, AutocommitError<E>>
    where
        's: 'dbtx,
        for<'r, 'o> F: Fn(
            &'r mut DatabaseTransaction<'o>,
            PhantomBound<'dbtx, 'o>,
        ) -> BoxFuture<'r, Result<T, E>>,
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
                    warn!(
                        target: LOG_DB,
                        curr_attempts, "Database commit failed in an autocommit block"
                    );
                    if max_attempts
                        .map(|max_att| max_att <= curr_attempts)
                        .unwrap_or(false)
                    {
                        return Err(AutocommitError::CommitFailed {
                            attempts: curr_attempts,
                            last_error: err,
                        });
                    }
                }
            }
            let delay = (2u64.pow(curr_attempts.min(7) as u32) * 10).min(1000);
            let delay = rand::thread_rng().gen_range(delay..(2 * delay));
            crate::task::sleep(Duration::from_millis(delay)).await;
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
                    trace!(
                        "get_value: Decoding {} from bytes {:?}",
                        std::any::type_name::<K::Value>(),
                        value_bytes
                    );
                    K::Value::from_bytes(&value_bytes, &self.module_decoders)
                        .expect("Unrecoverable error when decoding the database value")
                });

            if let Some(value) = checker(maybe_value_bytes) {
                return (
                    value,
                    DatabaseTransaction::new(tx, self.module_decoders.clone()),
                );
            } else {
                // key not found, try again
                notify.await;
                // if miss a notification between await and next register, it is
                // fine. because we are going check the database
            }
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
    let mut prefix = vec![MODULE_GLOBAL_PREFIX];
    module_instance_id
        .consensus_encode(&mut prefix)
        .expect("Error encoding module instance id as prefix");
    prefix
}

/// A database that wraps an `inner` one and adds a prefix to all operations,
/// effectively creating an isolated partition.
#[derive(Clone, Debug)]
struct PrefixDatabase<Inner>
where
    Inner: Debug,
{
    prefix: Vec<u8>,
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
            prefix: self.prefix.clone(),
        })
    }
    async fn register(&self, key: &[u8]) {
        self.inner.register(&self.get_full_key(key)).await
    }

    async fn notify(&self, key: &[u8]) {
        self.inner.notify(&self.get_full_key(key)).await
    }

    fn prefix_len(&self) -> usize {
        self.inner.prefix_len() + self.prefix.len()
    }
}

/// A database transactions that wraps an `inner` one and adds a prefix to all
/// operations, effectively creating an isolated partition.
///
/// Produced by [`PrefixDatabase`].
struct PrefixDatabaseTransaction<Inner> {
    inner: Inner,
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

    fn adapt_prefix_stream(stream: PrefixStream<'_>, prefix_len: usize) -> PrefixStream<'_> {
        Box::pin(stream.map(move |(k, v)| (k[prefix_len..].to_owned(), v))) /* as Pin<Box<dyn Stream<Item =
                                                                             * _>>> */
    }
}

#[apply(async_trait_maybe_send!)]
impl<Inner> IDatabaseTransaction for PrefixDatabaseTransaction<Inner>
where
    Inner: IDatabaseTransaction,
{
    async fn commit_tx(&mut self) -> Result<()> {
        self.inner.commit_tx().await
    }

    fn prefix_len(&self) -> usize {
        self.inner.prefix_len() + self.prefix.len()
    }
}

#[apply(async_trait_maybe_send!)]
impl<Inner> IDatabaseTransactionOpsCore for PrefixDatabaseTransaction<Inner>
where
    Inner: IDatabaseTransactionOpsCore,
{
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let key = self.get_full_key(key);
        self.inner.raw_insert_bytes(&key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let key = self.get_full_key(key);
        self.inner.raw_get_bytes(&key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let key = self.get_full_key(key);
        self.inner.raw_remove_entry(&key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        let key = self.get_full_key(key_prefix);
        let stream = self.inner.raw_find_by_prefix(&key).await?;
        Ok(Self::adapt_prefix_stream(stream, self.prefix.len()))
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        let key = self.get_full_key(key_prefix);
        let stream = self
            .inner
            .raw_find_by_prefix_sorted_descending(&key)
            .await?;
        Ok(Self::adapt_prefix_stream(stream, self.prefix.len()))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        let key = self.get_full_key(key_prefix);
        self.inner.raw_remove_by_prefix(&key).await
    }
}

#[apply(async_trait_maybe_send!)]
impl<Inner> IDatabaseTransactionOps for PrefixDatabaseTransaction<Inner>
where
    Inner: IDatabaseTransactionOps,
{
    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        self.inner.rollback_tx_to_savepoint().await
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        self.set_tx_savepoint().await
    }
}

/// Core raw a operations database transactions supports
///
/// Used to enforce the same signature on all types supporting it
#[apply(async_trait_maybe_send!)]
pub trait IDatabaseTransactionOpsCore: MaybeSend {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>>;

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Returns an stream of key-value pairs with keys that start with
    /// `key_prefix`. No particular ordering is guaranteed.
    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>>;

    /// Same as [`Self::raw_find_by_prefix`] but the order is descending by key.
    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>>;

    /// Delete keys matching prefix
    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()>;
}

#[apply(async_trait_maybe_send!)]
impl<T> IDatabaseTransactionOpsCore for Box<T>
where
    T: IDatabaseTransactionOpsCore + ?Sized,
{
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        (**self).raw_insert_bytes(key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        (**self).raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        (**self).raw_remove_entry(key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        (**self).raw_find_by_prefix(key_prefix).await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        (**self)
            .raw_find_by_prefix_sorted_descending(key_prefix)
            .await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        (**self).raw_remove_by_prefix(key_prefix).await
    }
}

#[apply(async_trait_maybe_send!)]
impl<T> IDatabaseTransactionOpsCore for &mut T
where
    T: IDatabaseTransactionOpsCore + ?Sized,
{
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        (**self).raw_insert_bytes(key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        (**self).raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        (**self).raw_remove_entry(key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        (**self).raw_find_by_prefix(key_prefix).await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        (**self)
            .raw_find_by_prefix_sorted_descending(key_prefix)
            .await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        (**self).raw_remove_by_prefix(key_prefix).await
    }
}

/// Additional operations (only some) database transactions expose, on top of
/// [`IDatabaseTransactionOpsCore`]
///
/// In certain contexts exposing these operations would be a problem, so they
/// are moved to a separate trait.
#[apply(async_trait_maybe_send!)]
pub trait IDatabaseTransactionOps: IDatabaseTransactionOpsCore + MaybeSend {
    /// Create a savepoint during the transaction that can be rolled back to
    /// using rollback_tx_to_savepoint. Rolling back to the savepoint will
    /// atomically remove the writes that were applied since the savepoint
    /// was created.
    ///
    /// Warning: Avoid using this in fedimint client code as not all database
    /// transaction implementations will support setting a savepoint during
    /// a transaction.
    async fn set_tx_savepoint(&mut self) -> Result<()>;

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()>;
}

#[apply(async_trait_maybe_send!)]
impl<T> IDatabaseTransactionOps for Box<T>
where
    T: IDatabaseTransactionOps + ?Sized,
{
    async fn set_tx_savepoint(&mut self) -> Result<()> {
        (**self).set_tx_savepoint().await
    }

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        (**self).rollback_tx_to_savepoint().await
    }
}

#[apply(async_trait_maybe_send!)]
impl<T> IDatabaseTransactionOps for &mut T
where
    T: IDatabaseTransactionOps + ?Sized,
{
    async fn set_tx_savepoint(&mut self) -> Result<()> {
        (**self).set_tx_savepoint().await
    }

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        (**self).rollback_tx_to_savepoint().await
    }
}

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
impl<'a, T> IDatabaseTransactionOpsCoreTyped<'a> for T
where
    T: IDatabaseTransactionOpsCore + WithDecoders,
{
    async fn get_value<K>(&mut self, key: &K) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
    {
        let raw = self
            .raw_get_bytes(&key.to_bytes())
            .await
            .expect("Unrecoverable error occurred while reading and entry from the database");
        raw.map(|value_bytes| {
            decode_value::<K::Value>(&value_bytes, self.decoders())
                .expect("Unrecoverable error when decoding the database value")
        })
    }

    async fn insert_entry<K>(&mut self, key: &K, value: &K::Value) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
        K::Value: MaybeSend + MaybeSync,
    {
        self.raw_insert_bytes(&key.to_bytes(), &value.to_bytes())
            .await
            .expect("Unrecoverable error occurred while inserting entry into the database")
            .map(|value_bytes| {
                decode_value::<K::Value>(&value_bytes, self.decoders())
                    .expect("Unrecoverable error when decoding the database value")
            })
    }

    async fn insert_new_entry<K>(&mut self, key: &K, value: &K::Value)
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
        K::Value: MaybeSend + MaybeSync,
    {
        if let Some(prev) = self.insert_entry(key, value).await {
            warn!(
                target: LOG_DB,
                "Database overwriting element when expecting insertion of new
            entry. Key: {:?} Prev Value: {:?}",             key,
                prev,
            );
        }
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
                    let key = KP::Record::from_bytes(&key_bytes, &decoders)
                        .with_context(|| anyhow::anyhow!("key: {}", AbbreviateHexBytes(&key_bytes)))
                        .expect("Unrecoverable error reading DatabaseKey");
                    let value = decode_value(&value_bytes, &decoders)
                        .with_context(|| anyhow::anyhow!("key: {}", AbbreviateHexBytes(&key_bytes)))
                        .expect("Unrecoverable decoding DatabaseValue");
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
                    let key = KP::Record::from_bytes(&key_bytes, &decoders)
                        .with_context(|| anyhow::anyhow!("key: {}", AbbreviateHexBytes(&key_bytes)))
                        .expect("Unrecoverable error reading DatabaseKey");
                    let value = decode_value(&value_bytes, &decoders)
                        .with_context(|| anyhow::anyhow!("key: {}", AbbreviateHexBytes(&key_bytes)))
                        .expect("Unrecoverable decoding DatabaseValue");
                    (key, value)
                }),
        )
    }
    async fn remove_entry<K>(&mut self, key: &K) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
    {
        self.raw_remove_entry(&key.to_bytes())
            .await
            .expect("Unrecoverable error occurred while inserting removing entry from the database")
            .map(|value_bytes| {
                decode_value::<K::Value>(&value_bytes, self.decoders())
                    .expect("Unrecoverable error when decoding the database value")
            })
    }
    async fn remove_by_prefix<KP>(&mut self, key_prefix: &KP)
    where
        KP: DatabaseLookup + MaybeSend + MaybeSync,
    {
        self.raw_remove_by_prefix(&key_prefix.to_bytes())
            .await
            .expect("Unrecoverable error when removing entries from the database")
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
    async fn commit_tx(self) -> Result<()>;
}

/// Fedimint database transaction
///
/// See [`IDatabase`] for more info.
#[apply(async_trait_maybe_send!)]
pub trait IDatabaseTransaction: MaybeSend + IDatabaseTransactionOps {
    /// Commit the transaction
    async fn commit_tx(&mut self) -> Result<()>;

    /// The prefix len of this database instance
    fn prefix_len(&self) -> usize;
}

#[apply(async_trait_maybe_send!)]
impl<T> IDatabaseTransaction for Box<T>
where
    T: IDatabaseTransaction + ?Sized,
{
    async fn commit_tx(&mut self) -> Result<()> {
        (**self).commit_tx().await
    }
    fn prefix_len(&self) -> usize {
        (**self).prefix_len()
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a, T> IDatabaseTransaction for &'a mut T
where
    T: IDatabaseTransaction + ?Sized,
{
    async fn commit_tx(&mut self) -> Result<()> {
        (**self).commit_tx().await
    }
    fn prefix_len(&self) -> usize {
        (**self).prefix_len()
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

impl<Tx> BaseDatabaseTransaction<Tx>
where
    Tx: IRawDatabaseTransaction,
{
    fn new(dbtx: Tx, notifications: Arc<Notifications>) -> BaseDatabaseTransaction<Tx> {
        BaseDatabaseTransaction {
            raw: Some(dbtx),
            notifications,
            notify_queue: Some(NotifyQueue::new()),
        }
    }

    fn add_notification_key(&mut self, key: &[u8]) -> Result<()> {
        self.notify_queue
            .as_mut()
            .context("can not call add_notification_key after commit")?
            .add(&key);
        Ok(())
    }
}

#[apply(async_trait_maybe_send!)]
impl<Tx: IRawDatabaseTransaction> IDatabaseTransactionOpsCore for BaseDatabaseTransaction<Tx> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        self.add_notification_key(key)?;
        self.raw
            .as_mut()
            .context("Cannot insert into already consumed transaction")?
            .raw_insert_bytes(key, value)
            .await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.raw
            .as_mut()
            .context("Cannot retrieve from already consumed transaction")?
            .raw_get_bytes(key)
            .await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.add_notification_key(key)?;
        self.raw
            .as_mut()
            .context("Cannot remove from already consumed transaction")?
            .raw_remove_entry(key)
            .await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        self.raw
            .as_mut()
            .context("Cannot retrieve from already consumed transaction")?
            .raw_find_by_prefix(key_prefix)
            .await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        self.raw
            .as_mut()
            .context("Cannot retrieve from already consumed transaction")?
            .raw_find_by_prefix_sorted_descending(key_prefix)
            .await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        self.raw
            .as_mut()
            .context("Cannot remove from already consumed transaction")?
            .raw_remove_by_prefix(key_prefix)
            .await
    }
}

#[apply(async_trait_maybe_send!)]
impl<Tx: IRawDatabaseTransaction> IDatabaseTransactionOps for BaseDatabaseTransaction<Tx> {
    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        self.raw
            .as_mut()
            .context("Cannot rollback to a savepoint on an already consumed transaction")?
            .rollback_tx_to_savepoint()
            .await?;
        Ok(())
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        self.raw
            .as_mut()
            .context("Cannot set a tx savepoint on an already consumed transaction")?
            .set_tx_savepoint()
            .await?;
        Ok(())
    }
}

#[apply(async_trait_maybe_send!)]
impl<Tx: IRawDatabaseTransaction> IDatabaseTransaction for BaseDatabaseTransaction<Tx> {
    async fn commit_tx(&mut self) -> Result<()> {
        self.raw
            .take()
            .context("Cannot commit an already committed transaction")?
            .commit_tx()
            .await?;
        self.notifications.submit_queue(
            self.notify_queue
                .take()
                .expect("commit must be called only once"),
        );
        Ok(())
    }

    fn prefix_len(&self) -> usize {
        0
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
                debug!(
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

impl<'a, T> ops::Deref for MaybeRef<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            MaybeRef::Owned(o) => o,
            MaybeRef::Borrowed(r) => r,
        }
    }
}

impl<'a, T> ops::DerefMut for MaybeRef<'a, T> {
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

impl<'tx, Cap> WithDecoders for DatabaseTransaction<'tx, Cap> {
    fn decoders(&self) -> &ModuleDecoderRegistry {
        &self.decoders
    }
}

#[instrument(level = "trace", skip_all, fields(value_type = std::any::type_name::<V>()), err)]
fn decode_value<V: DatabaseValue>(
    value_bytes: &[u8],
    decoders: &ModuleDecoderRegistry,
) -> Result<V, DecodingError> {
    trace!(
        bytes = %AbbreviateHexBytes(value_bytes),
        "decoding value",
    );
    V::from_bytes(value_bytes, decoders)
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
                prefix,
            }),
            decoders: self.decoders,
            commit_tracker: self.commit_tracker,
            on_commit_hooks: self.on_commit_hooks,
            capability: self.capability,
        }
    }

    /// Get [`DatabaseTransaction`] isolated to a prefix of a given
    /// `module_instance_id`
    pub fn with_prefix_module_id<'a: 'tx>(
        self,
        module_instance_id: ModuleInstanceId,
    ) -> DatabaseTransaction<'a, Cap>
    where
        'tx: 'a,
    {
        let prefix = module_instance_id_to_byte_prefix(module_instance_id);
        self.with_prefix(prefix)
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
    ) -> DatabaseTransaction<'a, Cap>
    where
        'tx: 'a,
    {
        let prefix = module_instance_id_to_byte_prefix(module_instance_id);
        self.to_ref_with_prefix(prefix)
    }

    /// Is this `Database` a global, unpartitioned `Database`
    pub fn is_global(&self) -> bool {
        self.tx.prefix_len() == 0
    }

    /// `Err` if [`Self::is_global`] is not true
    pub fn ensure_global(&self) -> Result<()> {
        if !self.is_global() {
            bail!("Database instance not global");
        }

        Ok(())
    }

    /// `Err` if [`Self::is_global`] is true
    pub fn ensure_isolated(&self) -> Result<()> {
        if self.is_global() {
            bail!("Database instance not isolated");
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
    #[instrument(level = "debug", skip_all, ret)]
    pub fn on_commit(&mut self, f: maybe_add_send!(impl FnOnce() + 'static)) {
        self.on_commit_hooks.push(Box::new(f));
    }
}

impl<'tx> DatabaseTransaction<'tx, Committable> {
    pub fn new(
        dbtx: Box<dyn IDatabaseTransaction + 'tx>,
        decoders: ModuleDecoderRegistry,
    ) -> DatabaseTransaction<'tx, Committable> {
        DatabaseTransaction {
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

    pub async fn commit_tx_result(mut self) -> Result<()> {
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
impl<'a, Cap> IDatabaseTransactionOpsCore for DatabaseTransaction<'a, Cap>
where
    Cap: Send,
{
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        self.commit_tracker.has_writes = true;
        self.tx.raw_insert_bytes(key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.tx.raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.tx.raw_remove_entry(key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        self.tx.raw_find_by_prefix(key_prefix).await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        self.tx
            .raw_find_by_prefix_sorted_descending(key_prefix)
            .await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        self.commit_tracker.has_writes = true;
        self.tx.raw_remove_by_prefix(key_prefix).await
    }
}
#[apply(async_trait_maybe_send!)]
impl<'a> IDatabaseTransactionOps for DatabaseTransaction<'a, Committable> {
    async fn set_tx_savepoint(&mut self) -> Result<()> {
        self.tx.set_tx_savepoint().await
    }

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        self.tx.rollback_tx_to_savepoint().await
    }
}

impl<T> DatabaseKeyPrefix for T
where
    T: DatabaseLookup + crate::encoding::Encodable + Debug,
{
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec![<Self as DatabaseLookup>::Record::DB_PREFIX];
        self.consensus_encode(&mut data)
            .expect("Writing to vec is infallible");
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
    fn from_bytes(data: &[u8], modules: &ModuleDecoderRegistry) -> Result<Self, DecodingError> {
        if data.is_empty() {
            // TODO: build better coding errors, pretty useless right now
            return Err(DecodingError::wrong_length(1, 0));
        }

        if data[0] != Self::DB_PREFIX {
            return Err(DecodingError::wrong_prefix(Self::DB_PREFIX, data[0]));
        }

        <Self as crate::encoding::Decodable>::consensus_decode(
            &mut std::io::Cursor::new(&data[1..]),
            modules,
        )
        .map_err(|decode_error| DecodingError::Other(decode_error.0))
    }
}

impl<T> DatabaseValue for T
where
    T: Debug + Encodable + Decodable,
{
    fn from_bytes(data: &[u8], modules: &ModuleDecoderRegistry) -> Result<Self, DecodingError> {
        T::consensus_decode(&mut std::io::Cursor::new(data), modules)
            .map_err(|e| DecodingError::Other(e.0))
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes)
            .expect("writing to vec can't fail");
        bytes
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
    (key = $key:ty, value = $val:ty, db_prefix = $db_prefix:expr $(, notify_on_modify = $notify:tt)? $(,)?) => {
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

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct DatabaseVersionKey;

#[derive(Debug, Encodable, Decodable, Serialize, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct DatabaseVersion(pub u64);

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
    pub fn increment(&mut self) {
        self.0 += 1;
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
    #[error("Other decoding error: {0}")]
    Other(anyhow::Error),
}

impl DecodingError {
    pub fn other<E: Error + Send + Sync + 'static>(error: E) -> DecodingError {
        DecodingError::Other(anyhow::Error::from(error))
    }

    pub fn wrong_prefix(expected: u8, found: u8) -> DecodingError {
        DecodingError::WrongPrefix { expected, found }
    }

    pub fn wrong_length(expected: usize, found: usize) -> DecodingError {
        DecodingError::WrongLength { expected, found }
    }
}

#[macro_export]
macro_rules! push_db_pair_items {
    ($dbtx:ident, $prefix_type:expr, $key_type:ty, $value_type:ty, $map:ident, $key_literal:literal) => {
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
macro_rules! push_db_pair_items_no_serde {
    ($dbtx:ident, $prefix_type:expr, $key_type:ty, $value_type:ty, $map:ident, $key_literal:literal) => {
        let db_items =
            $crate::db::IDatabaseTransactionOpsCoreTyped::find_by_prefix($dbtx, &$prefix_type)
                .await
                .map(|(key, val)| {
                    (
                        $crate::encoding::Encodable::consensus_encode_to_hex(&key),
                        SerdeWrapper::from_encodable(val),
                    )
                })
                .collect::<BTreeMap<_, _>>()
                .await;

        $map.insert($key_literal.to_string(), Box::new(db_items));
    };
}

#[macro_export]
macro_rules! push_db_key_items {
    ($dbtx:ident, $prefix_type:expr, $key_type:ty, $map:ident, $key_literal:literal) => {
        let db_items =
            $crate::db::IDatabaseTransactionOpsCoreTyped::find_by_prefix($dbtx, &$prefix_type)
                .await
                .map(|(key, _)| key)
                .collect::<Vec<$key_type>>()
                .await;

        $map.insert($key_literal.to_string(), Box::new(db_items));
    };
}

/// MigrationMap is a BTreeMap that maps DatabaseVersions to async functions.
/// These functions are expected to "migrate" the database from the keyed
/// DatabaseVersion to DatabaseVersion + 1.
pub type MigrationMap = BTreeMap<
    DatabaseVersion,
    for<'r, 'tx> fn(
        &'r mut DatabaseTransaction<'tx>,
    ) -> Pin<Box<dyn futures::Future<Output = anyhow::Result<()>> + Send + 'r>>,
>;

/// `apply_migrations` iterates from the on disk database version for the module
/// up to `target_db_version` and executes all of the migrations that exist in
/// the `MigrationMap`. Each migration in `MigrationMap` updates the database to
/// have the correct on-disk structures that the code is expecting. The entire
/// migration process is atomic (i.e migration from 0->1 and 1->2 happen
/// atomically). This function is called before the module is initialized and as
/// long as the correct migrations are supplied in `MigrationMap`, the module
/// will be able to read and write from the database successfully.
pub async fn apply_migrations(
    db: &Database,
    kind: String,
    target_db_version: DatabaseVersion,
    migrations: MigrationMap,
    module_instance_id: Option<ModuleInstanceId>,
) -> Result<(), anyhow::Error> {
    let mut dbtx = if let Some(module_instance_id) = module_instance_id {
        db.begin_transaction()
            .await
            .with_prefix_module_id(module_instance_id)
    } else {
        db.begin_transaction().await
    };

    let disk_version = dbtx.get_value(&DatabaseVersionKey).await;

    let db_version = if let Some(disk_version) = disk_version {
        let mut current_db_version = disk_version;

        if current_db_version > target_db_version {
            return Err(anyhow::anyhow!(format!(
                "On disk database version for module {kind} was higher than the code database version."
            )));
        }

        while current_db_version < target_db_version {
            if let Some(migration) = migrations.get(&current_db_version) {
                info!(target: LOG_DB, "Migrating module {kind} from {current_db_version} to {target_db_version}");
                migration(&mut dbtx.to_ref_nc()).await?;
            } else {
                panic!("Missing migration for version {current_db_version}");
            }

            current_db_version.increment();
            dbtx.insert_entry(&DatabaseVersionKey, &current_db_version)
                .await;
        }

        current_db_version
    } else {
        dbtx.insert_entry(&DatabaseVersionKey, &target_db_version)
            .await;
        target_db_version
    };

    dbtx.commit_tx_result().await?;
    info!(target: LOG_DB, "{} module db version: {}", kind, db_version);
    Ok(())
}

#[allow(unused_imports)]
mod test_utils {
    use std::time::Duration;

    use futures::{Future, FutureExt, StreamExt};

    use super::{
        apply_migrations, Database, DatabaseTransaction, DatabaseVersion, DatabaseVersionKey,
        MigrationMap,
    };
    use crate::core::ModuleKind;
    use crate::db::mem_impl::MemDatabase;
    use crate::db::{IDatabaseTransactionOps, IDatabaseTransactionOpsCoreTyped};
    use crate::encoding::{Decodable, Encodable};
    use crate::module::registry::ModuleDecoderRegistry;

    pub async fn future_returns_shortly<F: Future>(fut: F) -> Option<F::Output> {
        crate::task::timeout(Duration::from_millis(10), fut)
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

    pub async fn verify_find_by_prefix(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&TestKey(55), &TestVal(9999)).await;
        dbtx.insert_entry(&TestKey(54), &TestVal(8888)).await;

        dbtx.insert_entry(&AltTestKey(55), &TestVal(7777)).await;
        dbtx.insert_entry(&AltTestKey(54), &TestVal(6666)).await;
        dbtx.commit_tx().await;

        // Verify finding by prefix returns the correct set of key pairs
        let mut dbtx = db.begin_transaction().await;

        let mut returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        returned_keys.sort();
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

        let mut returned_keys = dbtx
            .find_by_prefix(&AltDbPrefixTestPrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        returned_keys.sort();
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

    pub async fn verify_rollback_to_savepoint(db: Database) {
        let mut dbtx_rollback = db.begin_transaction().await;

        dbtx_rollback
            .insert_entry(&TestKey(20), &TestVal(2000))
            .await;

        dbtx_rollback
            .set_tx_savepoint()
            .await
            .expect("Error setting transaction savepoint");

        dbtx_rollback
            .insert_entry(&TestKey(21), &TestVal(2001))
            .await;

        assert_eq!(
            dbtx_rollback.get_value(&TestKey(20)).await,
            Some(TestVal(2000))
        );
        assert_eq!(
            dbtx_rollback.get_value(&TestKey(21)).await,
            Some(TestVal(2001))
        );

        dbtx_rollback
            .rollback_tx_to_savepoint()
            .await
            .expect("Error setting transaction savepoint");

        assert_eq!(
            dbtx_rollback.get_value(&TestKey(20)).await,
            Some(TestVal(2000))
        );

        assert_eq!(dbtx_rollback.get_value(&TestKey(21)).await, None);

        // Commit to suppress the warning message
        dbtx_rollback.commit_tx().await;
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
                if let TestKey(100) = key {
                    assert!(value.eq(&TestVal(101)));
                }
                returned_keys + 1
            })
            .await;

        assert_eq!(returned_keys, expected_keys);
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
                };
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
                };
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
                if let PercentTestKey(101) = key {
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
                };
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
                };
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
            let mut test_module_dbtx = test_dbtx.to_ref_with_prefix_module_id(TEST_MODULE_PREFIX);

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
            let mut alt_module_dbtx = alt_dbtx.to_ref_with_prefix_module_id(ALT_MODULE_PREFIX);

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
        let mut test_module_dbtx = test_dbtx.to_ref_with_prefix_module_id(TEST_MODULE_PREFIX);
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
                };
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

        dbtx.insert_new_entry(&DatabaseVersionKey, &DatabaseVersion(0))
            .await;
        dbtx.commit_tx().await;

        let mut migrations = MigrationMap::new();

        migrations.insert(DatabaseVersion(0), move |dbtx| {
            migrate_test_db_version_0(dbtx).boxed()
        });

        apply_migrations(
            &db,
            "TestModule".to_string(),
            DatabaseVersion(1),
            migrations,
            None,
        )
        .await
        .expect("Error applying migrations for TestModule");

        // Verify that the migrations completed successfully
        let mut dbtx = db.begin_transaction().await;

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
    async fn migrate_test_db_version_0<'a, 'b>(
        dbtx: &'b mut DatabaseTransaction<'a>,
    ) -> Result<(), anyhow::Error> {
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

        use anyhow::anyhow;
        use async_trait::async_trait;

        use crate::db::{
            AutocommitError, BaseDatabaseTransaction, IDatabaseTransaction,
            IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase,
            IRawDatabaseTransaction,
        };
        use crate::ModuleDecoderRegistry;

        #[derive(Debug)]
        struct FakeDatabase;

        #[async_trait]
        impl IRawDatabase for FakeDatabase {
            type Transaction<'a> = FakeTransaction<'a>;
            async fn begin_transaction(&self) -> FakeTransaction {
                FakeTransaction(PhantomData)
            }
        }

        #[derive(Debug)]
        struct FakeTransaction<'a>(PhantomData<&'a ()>);

        #[async_trait]
        impl<'a> IDatabaseTransactionOpsCore for FakeTransaction<'a> {
            async fn raw_insert_bytes(
                &mut self,
                _key: &[u8],
                _value: &[u8],
            ) -> anyhow::Result<Option<Vec<u8>>> {
                unimplemented!()
            }

            async fn raw_get_bytes(&mut self, _key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
                unimplemented!()
            }

            async fn raw_remove_entry(&mut self, _key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
                unimplemented!()
            }

            async fn raw_find_by_prefix(
                &mut self,
                _key_prefix: &[u8],
            ) -> anyhow::Result<crate::db::PrefixStream<'_>> {
                unimplemented!()
            }

            async fn raw_remove_by_prefix(&mut self, _key_prefix: &[u8]) -> anyhow::Result<()> {
                unimplemented!()
            }

            async fn raw_find_by_prefix_sorted_descending(
                &mut self,
                _key_prefix: &[u8],
            ) -> anyhow::Result<crate::db::PrefixStream<'_>> {
                unimplemented!()
            }
        }

        #[async_trait]
        impl<'a> IDatabaseTransactionOps for FakeTransaction<'a> {
            async fn rollback_tx_to_savepoint(&mut self) -> anyhow::Result<()> {
                unimplemented!()
            }

            async fn set_tx_savepoint(&mut self) -> anyhow::Result<()> {
                unimplemented!()
            }
        }

        #[async_trait]
        impl<'a> IRawDatabaseTransaction for FakeTransaction<'a> {
            async fn commit_tx(self) -> anyhow::Result<()> {
                Err(anyhow!("Can't commit!"))
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
                assert_eq!(failed_attempts, 5)
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
> + 'r
where
    'inner: 'r,
    KP: DatabaseLookup,
    KP::Record: DatabaseKey,
{
    debug!("find by prefix sorted descending");
    let prefix_bytes = key_prefix.to_bytes();
    tx.raw_find_by_prefix_sorted_descending(&prefix_bytes)
        .await
        .expect("Error doing prefix search in database")
        .map(move |(key_bytes, value_bytes)| {
            let key = KP::Record::from_bytes(&key_bytes, &decoders)
                .with_context(|| anyhow::anyhow!("key: {}", AbbreviateHexBytes(&key_bytes)))
                .expect("Unrecoverable error reading DatabaseKey");
            let value = decode_value(&value_bytes, &decoders)
                .with_context(|| anyhow::anyhow!("key: {}", AbbreviateHexBytes(&key_bytes)))
                .expect("Unrecoverable decoding DatabaseValue");
            (key, value)
        })
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;

    use super::mem_impl::MemDatabase;
    use super::*;
    use crate::task::spawn;

    async fn waiter(db: &Database, key: TestKey) -> tokio::task::JoinHandle<TestVal> {
        let db = db.clone();
        let (tx, rx) = oneshot::channel::<()>();
        let join_handle = spawn("wait key exists", async move {
            let sub = db.wait_key_exists(&key);
            tx.send(()).unwrap();
            sub.await
        })
        .expect("some handle on non-wasm");
        rx.await.unwrap();
        join_handle
    }

    #[tokio::test]
    async fn test_wait_key_before_transaction() {
        let key = TestKey(1);
        let val = TestVal(2);
        let db = MemDatabase::new().into_database();

        let key_task = waiter(&db, TestKey(1)).await;

        let mut tx = db.begin_transaction().await;
        tx.insert_new_entry(&key, &val).await;
        tx.commit_tx().await;

        assert_eq!(
            future_returns_shortly(async { key_task.await.unwrap() }).await,
            Some(TestVal(2)),
            "should notify"
        );
    }

    #[tokio::test]
    async fn test_wait_key_before_insert() {
        let key = TestKey(1);
        let val = TestVal(2);
        let db = MemDatabase::new().into_database();

        let mut tx = db.begin_transaction().await;
        let key_task = waiter(&db, TestKey(1)).await;
        tx.insert_new_entry(&key, &val).await;
        tx.commit_tx().await;

        assert_eq!(
            future_returns_shortly(async { key_task.await.unwrap() }).await,
            Some(TestVal(2)),
            "should notify"
        );
    }

    #[tokio::test]
    async fn test_wait_key_after_insert() {
        let key = TestKey(1);
        let val = TestVal(2);
        let db = MemDatabase::new().into_database();

        let mut tx = db.begin_transaction().await;
        tx.insert_new_entry(&key, &val).await;

        let key_task = waiter(&db, TestKey(1)).await;

        tx.commit_tx().await;

        assert_eq!(
            future_returns_shortly(async { key_task.await.unwrap() }).await,
            Some(TestVal(2)),
            "should notify"
        );
    }

    #[tokio::test]
    async fn test_wait_key_after_commit() {
        let key = TestKey(1);
        let val = TestVal(2);
        let db = MemDatabase::new().into_database();

        let mut tx = db.begin_transaction().await;
        tx.insert_new_entry(&key, &val).await;
        tx.commit_tx().await;

        let key_task = waiter(&db, TestKey(1)).await;
        assert_eq!(
            future_returns_shortly(async { key_task.await.unwrap() }).await,
            Some(TestVal(2)),
            "should notify"
        );
    }

    #[tokio::test]
    async fn test_wait_key_isolated_db() {
        let module_instance_id = 10;
        let key = TestKey(1);
        let val = TestVal(2);
        let db = MemDatabase::new().into_database();
        let db = db.with_prefix_module_id(module_instance_id);

        let key_task = waiter(&db, TestKey(1)).await;

        let mut tx = db.begin_transaction().await;
        tx.insert_new_entry(&key, &val).await;
        tx.commit_tx().await;

        assert_eq!(
            future_returns_shortly(async { key_task.await.unwrap() }).await,
            Some(TestVal(2)),
            "should notify"
        );
    }

    #[tokio::test]
    async fn test_wait_key_isolated_tx() {
        let module_instance_id = 10;
        let key = TestKey(1);
        let val = TestVal(2);
        let db = MemDatabase::new().into_database();

        let key_task = waiter(&db.with_prefix_module_id(module_instance_id), TestKey(1)).await;

        let mut tx = db.begin_transaction().await;
        let mut tx_mod = tx.to_ref_with_prefix_module_id(module_instance_id);
        tx_mod.insert_new_entry(&key, &val).await;
        drop(tx_mod);
        tx.commit_tx().await;

        assert_eq!(
            future_returns_shortly(async { key_task.await.unwrap() }).await,
            Some(TestVal(2)),
            "should notify"
        );
    }

    #[tokio::test]
    async fn test_wait_key_no_transaction() {
        let db = MemDatabase::new().into_database();

        let key_task = waiter(&db, TestKey(1)).await;
        assert_eq!(
            future_returns_shortly(async { key_task.await.unwrap() }).await,
            None,
            "should not notify"
        );
    }
}
