use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result};
use fedimint_core::util::BoxFuture;
use fedimint_logging::LOG_DB;
use futures::{Stream, StreamExt};
use macro_rules_attribute::apply;
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

use self::notifications::{Notifications, NotifyingTransaction};
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

#[apply(async_trait_maybe_send!)]
pub trait IDatabase: Debug + MaybeSend + MaybeSync + 'static {
    async fn begin_transaction<'a>(&'a self) -> Box<dyn ISingleUseDatabaseTransaction<'a>>;
}

#[derive(Clone, Debug)]
pub struct Database {
    inner_db: Arc<DatabaseInner<dyn IDatabase>>,
    module_instance_id: Option<ModuleInstanceId>,
}

// NOTE: `Db` is used instead of just `dyn IDatabase`
// because it will impossible to construct otherwise
#[derive(Debug)]
struct DatabaseInner<Db: IDatabase + ?Sized> {
    notifications: Notifications,
    module_decoders: ModuleDecoderRegistry,
    db: Box<Db>,
}

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

impl Database {
    /// Creates a new Fedimint database from any object implementing
    /// [`IDatabase`]. For more flexibility see also [`Database::new_from_box`].
    pub fn new(db: impl IDatabase + 'static, module_decoders: ModuleDecoderRegistry) -> Self {
        let inner = DatabaseInner::<dyn IDatabase> {
            db: Box::new(db),
            notifications: Notifications::new(),
            module_decoders,
        };

        Self {
            inner_db: Arc::new(inner),
            module_instance_id: None,
        }
    }

    /// Creates a new Fedimint database from a `Box<dyn IDatabase>`, allowing
    /// the caller to have a dynamic database backend that can choose
    /// implementations at runtime, while not needing to bind decoders that
    /// might only be available later.
    pub fn new_from_box(db: Box<dyn IDatabase>, module_decoders: ModuleDecoderRegistry) -> Self {
        let inner = DatabaseInner {
            db,
            notifications: Notifications::new(),
            module_decoders,
        };

        Self {
            inner_db: Arc::new(inner),
            module_instance_id: None,
        }
    }

    pub fn new_isolated(&self, module_instance_id: ModuleInstanceId) -> Self {
        if self.module_instance_id.is_some() {
            panic!("Cannot isolate and already isolated database.");
        }

        let db = self.inner_db.clone();
        Self {
            inner_db: db,
            module_instance_id: Some(module_instance_id),
        }
    }

    pub async fn begin_transaction(&self) -> DatabaseTransaction {
        let dbtx = DatabaseTransaction::new(
            self.inner_db.db.begin_transaction().await,
            self.inner_db.module_decoders.clone(),
            &self.inner_db.notifications,
        );

        match self.module_instance_id {
            Some(module_instance_id) => dbtx.new_module_tx(module_instance_id),
            None => dbtx,
        }
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
    pub async fn autocommit<'s: 'dt, 'dt, F, T, E>(
        &'s self,
        tx_fn: F,
        max_attempts: Option<usize>,
    ) -> Result<T, AutocommitError<E>>
    where
        for<'a> F: Fn(&'a mut DatabaseTransaction<'dt>) -> BoxFuture<'a, Result<T, E>>,
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

            match tx_fn(&mut dbtx).await {
                Ok(val) => {
                    let _timing /* logs on drop */ = timing::TimeReporter::new("autocmmit - commit_tx");

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
                }
                Err(err) => {
                    return Err(AutocommitError::ClosureError {
                        attempts: curr_attempts,
                        error: err,
                    });
                }
            };
        } // end of loop
    }

    /// Waits for key to be notified.
    ///
    /// Calls the `checker` when value of the key may have changed.
    /// Returns the value when `checker` returns a `Some(T)`.
    pub async fn wait_key_check<'a, K, T>(
        &'a self,
        key: &K,
        checker: impl Fn(Option<K::Value>) -> Option<T>,
    ) -> (T, DatabaseTransaction<'a>)
    where
        K: DatabaseKey + DatabaseRecord + DatabaseKeyWithNotify,
    {
        let key_bytes = if let Some(module_id) = self.module_instance_id {
            let mut prefix_bytes = vec![MODULE_GLOBAL_PREFIX];
            module_id
                .consensus_encode(&mut prefix_bytes)
                .expect("Error encoding module instance id as prefix");
            prefix_bytes.extend(key.to_bytes());
            prefix_bytes
        } else {
            key.to_bytes()
        };
        loop {
            // register for notification
            let notify = self.inner_db.notifications.register(&key_bytes);

            // check for value in db
            let mut tx = self.inner_db.db.begin_transaction().await;

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
                    K::Value::from_bytes(&value_bytes, &self.inner_db.module_decoders)
                        .expect("Unrecoverable error when decoding the database value")
                });

            if let Some(value) = checker(maybe_value_bytes) {
                return (
                    value,
                    DatabaseTransaction::new(
                        tx,
                        self.inner_db.module_decoders.clone(),
                        &self.inner_db.notifications,
                    ),
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

/// Fedimint requires that the database implementation implement Snapshot
/// Isolation. Snapshot Isolation is a database isolation level that guarantees
/// consistent reads from the time that the snapshot was created (at transaction
/// creation time). Transactions with Snapshot Isolation level will only commit
/// if there has been no write to the modified keys since the snapshot (i.e.
/// write-write conflicts are prevented).
///
/// Specifically, Fedimint expects the database implementation to prevent the
/// following anomalies:
///
/// Non-Readable Write: TX1 writes (K1, V1) at time t but cannot read (K1, V1)
/// at time (t + i)
///
/// Dirty Read: TX1 is able to read TX2's uncommitted writes.
///
/// Non-Repeatable Read: TX1 reads (K1, V1) at time t and retrieves (K1, V2) at
/// time (t + i) where V1 != V2.
///
/// Phantom Record: TX1 retrieves X number of records for a prefix at time t and
/// retrieves Y number of records for the same prefix at time (t + i).
///
/// Lost Writes: TX1 writes (K1, V1) at the same time as TX2 writes (K1, V2). V2
/// overwrites V1 as the value for K1 (write-write conflict).
///
/// | Type     | Non-Readable Write | Dirty Read | Non-Repeatable Read | Phantom
/// Record | Lost Writes | | -------- | ------------------ | ---------- |
/// ------------------- | -------------- | ----------- | | MemoryDB | Prevented
/// | Prevented  | Prevented           | Prevented      | Possible    |
/// | RocksDB  | Prevented          | Prevented  | Prevented           |
/// Prevented      | Prevented   | | Sqlite   | Prevented          | Prevented
/// | Prevented           | Prevented      | Prevented   |
#[apply(async_trait_maybe_send!)]
pub trait IDatabaseTransaction<'a>: 'a + MaybeSend {
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

    /// Default implementation is a combination of [`Self::raw_find_by_prefix`]
    /// + loop over [`Self::raw_remove_entry`]
    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        let keys = self
            .raw_find_by_prefix(key_prefix)
            .await?
            .map(|kv| kv.0)
            .collect::<Vec<_>>()
            .await;
        for key in keys {
            self.raw_remove_entry(key.as_slice()).await?;
        }
        Ok(())
    }

    async fn commit_tx(self) -> Result<()>;

    async fn rollback_tx_to_savepoint(&mut self);

    /// Create a savepoint during the transaction that can be rolled back to
    /// using rollback_tx_to_savepoint. Rolling back to the savepoint will
    /// atomically remove the writes that were applied since the savepoint
    /// was created.
    ///
    /// Warning: Avoid using this in fedimint client code as not all database
    /// transaction implementations will support setting a savepoint during
    /// a transaction.
    async fn set_tx_savepoint(&mut self);

    fn add_notification_key(&mut self, _key: &[u8]) -> Result<()> {
        anyhow::bail!("add_notification_key called without NotifyingTransaction")
    }
}

/// `ISingleUseDatabaseTransaction` re-defines the functions from
/// `IDatabaseTransaction` but does not consumed `self` when committing to the
/// database. This allows for wrapper structs to more easily borrow
/// `ISingleUseDatabaseTransaction` without needing to make additional
/// allocations.
#[apply(async_trait_maybe_send!)]
pub trait ISingleUseDatabaseTransaction<'a>: 'a + MaybeSend {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>>;

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>>;

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>>;

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()>;

    async fn commit_tx(&mut self) -> Result<()>;

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()>;

    async fn set_tx_savepoint(&mut self) -> Result<()>;

    fn add_notification_key(&mut self, _key: &[u8]) -> Result<()>;
}

/// Struct that implements `ISingleUseDatabaseTransaction` and can be wrapped
/// easier in other structs since it does not consumed `self` by move.
pub struct SingleUseDatabaseTransaction<'a, Tx: IDatabaseTransaction<'a> + MaybeSend>(
    Option<Tx>,
    &'a PhantomData<()>,
);

impl<'a, Tx: IDatabaseTransaction<'a> + MaybeSend> SingleUseDatabaseTransaction<'a, Tx> {
    pub fn new(dbtx: Tx) -> SingleUseDatabaseTransaction<'a, Tx> {
        SingleUseDatabaseTransaction(Some(dbtx), &PhantomData)
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a, Tx: IDatabaseTransaction<'a> + MaybeSend> ISingleUseDatabaseTransaction<'a>
    for SingleUseDatabaseTransaction<'a, Tx>
{
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        self.0
            .as_mut()
            .context("Cannot insert into already consumed transaction")?
            .raw_insert_bytes(key, value)
            .await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.0
            .as_mut()
            .context("Cannot retrieve from already consumed transaction")?
            .raw_get_bytes(key)
            .await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.0
            .as_mut()
            .context("Cannot remove from already consumed transaction")?
            .raw_remove_entry(key)
            .await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        self.0
            .as_mut()
            .context("Cannot retrieve from already consumed transaction")?
            .raw_find_by_prefix(key_prefix)
            .await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        self.0
            .as_mut()
            .context("Cannot retrieve from already consumed transaction")?
            .raw_find_by_prefix_sorted_descending(key_prefix)
            .await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        self.0
            .as_mut()
            .context("Cannot remove from already consumed transaction")?
            .raw_remove_by_prefix(key_prefix)
            .await
    }

    async fn commit_tx(&mut self) -> Result<()> {
        self.0
            .take()
            .context("Cannot commit an already committed transaction")?
            .commit_tx()
            .await
    }

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        self.0
            .as_mut()
            .context("Cannot rollback to a savepoint on an already consumed transaction")?
            .rollback_tx_to_savepoint()
            .await;
        Ok(())
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        self.0
            .as_mut()
            .context("Cannot set a tx savepoint on an already consumed transaction")?
            .set_tx_savepoint()
            .await;
        Ok(())
    }

    fn add_notification_key(&mut self, key: &[u8]) -> Result<()> {
        self.0
            .as_mut()
            .context("Cannot add notification on an already consumed transaction")?
            .add_notification_key(key)
    }
}

// TODO: use macro again
#[doc = " A handle to a type-erased database implementation"]
#[derive(Clone)]
pub struct CommitTracker {
    is_committed: bool,
    has_writes: bool,
}

impl Drop for CommitTracker {
    fn drop(&mut self) {
        if self.has_writes && !self.is_committed {
            warn!(
                target: LOG_DB,
                "DatabaseTransaction has writes and has not called commit."
            );
        }
    }
}

/// `CommittableIsolatedDatabaseTransaction` is a private, isolated database
/// transaction that consumes an existing `ISingleUseDatabaseTransaction`.
/// Unlike `IsolatedDatabaseTransaction`,
/// `CommittableIsolatedDatabaseTransaction` can be owned by the module as long
/// as it has a handle to the isolated `Database`. This allows the module to
/// make changes only affecting it's own portion of the database and also being
/// able to commit those changes. From the module's perspective, the `Database`
/// is isolated and calling `begin_transaction` will always produce a
/// `CommittableIsolatedDatabaseTransaction`, which is isolated from other
/// modules by prepending a prefix to each key.
///
/// `CommittableIsolatedDatabaseTransaction` cannot be used as an atomic
/// database transaction across modules.
struct CommittableIsolatedDatabaseTransaction<'a> {
    dbtx: Box<dyn ISingleUseDatabaseTransaction<'a>>,
    prefix: ModuleInstanceId,
}

impl<'a> CommittableIsolatedDatabaseTransaction<'a> {
    pub fn new(
        dbtx: Box<dyn ISingleUseDatabaseTransaction<'a>>,
        prefix: ModuleInstanceId,
    ) -> CommittableIsolatedDatabaseTransaction<'a> {
        CommittableIsolatedDatabaseTransaction { dbtx, prefix }
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a> ISingleUseDatabaseTransaction<'a> for CommittableIsolatedDatabaseTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut isolated = IsolatedDatabaseTransaction::new(self.dbtx.as_mut(), Some(&self.prefix));
        isolated.raw_insert_bytes(key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut isolated = IsolatedDatabaseTransaction::new(self.dbtx.as_mut(), Some(&self.prefix));
        isolated.raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut isolated = IsolatedDatabaseTransaction::new(self.dbtx.as_mut(), Some(&self.prefix));
        isolated.raw_remove_entry(key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        let prefix_with_module = IsolatedDatabaseTransaction::prefix_with_module(&self.prefix);
        IsolatedDatabaseTransaction::<u16>::raw_find_by_prefix(
            prefix_with_module,
            self.dbtx.as_mut(),
            key_prefix,
        )
        .await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        let prefix_with_module = IsolatedDatabaseTransaction::prefix_with_module(&self.prefix);
        IsolatedDatabaseTransaction::<u16>::raw_find_by_prefix_sorted_descending(
            prefix_with_module,
            self.dbtx.as_mut(),
            key_prefix,
        )
        .await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        let mut isolated = IsolatedDatabaseTransaction::new(self.dbtx.as_mut(), Some(&self.prefix));
        isolated.raw_remove_by_prefix(key_prefix).await
    }

    async fn commit_tx(&mut self) -> Result<()> {
        self.dbtx.commit_tx().await
    }

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        let mut isolated = IsolatedDatabaseTransaction::new(self.dbtx.as_mut(), Some(&self.prefix));
        isolated.rollback_tx_to_savepoint().await
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        let mut isolated = IsolatedDatabaseTransaction::new(self.dbtx.as_mut(), Some(&self.prefix));
        isolated.set_tx_savepoint().await
    }

    fn add_notification_key(&mut self, key: &[u8]) -> Result<()> {
        let mut isolated = IsolatedDatabaseTransaction::new(self.dbtx.as_mut(), Some(&self.prefix));
        isolated.add_notification_key(key)
    }
}

/// `ModuleDatabaseTransaction` is the public wrapper structure that allows
/// modules to modify the database. It takes a `ISingleUseDatabaseTransaction`
/// that handles the details of interacting with the database. The APIs that the
/// modules are allowed to interact with are a subset of `DatabaseTransaction`,
/// since modules do not manage the lifetime of database transactions.
/// Committing to the database or rolling back a transaction is not exposed.
pub struct ModuleDatabaseTransaction<
    'isolated,
    T: MaybeSend + Encodable + 'isolated = ModuleInstanceId,
> {
    isolated_tx: Box<dyn ISingleUseDatabaseTransaction<'isolated>>,
    decoders: &'isolated ModuleDecoderRegistry,
    commit_tracker: &'isolated mut CommitTracker,
    _marker: PhantomData<T>,
}

impl<'isolated, T: MaybeSend + Encodable> ModuleDatabaseTransaction<'isolated, T> {
    pub fn new<'parent: 'isolated>(
        dbtx: &'isolated mut dyn ISingleUseDatabaseTransaction<'parent>,
        module_prefix: Option<&T>,
        decoders: &'isolated ModuleDecoderRegistry,
        commit_tracker: &'isolated mut CommitTracker,
    ) -> ModuleDatabaseTransaction<'isolated, T> {
        let isolated = IsolatedDatabaseTransaction::new(dbtx, module_prefix);

        ModuleDatabaseTransaction {
            isolated_tx: Box::new(isolated),
            decoders,
            commit_tracker,
            _marker: PhantomData::<T>,
        }
    }

    #[instrument(level = "debug", skip_all, fields(?key))]
    pub async fn get_value<K>(&mut self, key: &K) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = self
            .isolated_tx
            .raw_get_bytes(&key_bytes)
            .await
            .expect("Unrecoverable error when reading from database");
        match value_bytes {
            Some(value_bytes) => Some(
                decode_value::<K::Value>(&value_bytes, self.decoders)
                    .expect("Unrecoverable error when decoding the database value"),
            ),
            None => None,
        }
    }

    pub async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        self.isolated_tx.raw_find_by_prefix(key_prefix).await
    }

    #[instrument(level = "debug", skip_all, fields(key = ?key_prefix))]
    pub async fn find_by_prefix<KP>(
        &mut self,
        key_prefix: &KP,
    ) -> impl Stream<
        Item = (
            KP::Record,
            <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value,
        ),
    > + '_
    where
        KP: DatabaseLookup,
        KP::Record: DatabaseKey,
    {
        debug!("find by prefix");
        let decoders = self.decoders.clone();
        let prefix_bytes = key_prefix.to_bytes();
        self.isolated_tx
            .raw_find_by_prefix(&prefix_bytes)
            .await
            .expect("Error doing prefix search in database")
            .map(move |(key_bytes, value_bytes)| {
                let key = KP::Record::from_bytes(&key_bytes, &decoders)
                    .expect("Unrecoverable error reading the DatabaseKey");
                let value = decode_value(&value_bytes, &decoders)
                    .expect("Unrecoverable error decoding the DatabaseValue");
                (key, value)
            })
    }

    #[instrument(level = "debug", skip_all, fields(key = ?key_prefix))]
    pub async fn find_by_prefix_sorted_descending<KP>(
        &mut self,
        key_prefix: &KP,
    ) -> impl Stream<
        Item = (
            KP::Record,
            <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value,
        ),
    > + '_
    where
        KP: DatabaseLookup,
        KP::Record: DatabaseKey,
    {
        find_by_prefix_sorted_descending(
            self.isolated_tx.as_mut(),
            self.decoders.clone(),
            key_prefix,
        )
        .await
    }

    #[instrument(level = "debug", skip_all, fields(?key))]
    fn add_notification_key<K>(&mut self, key: &K)
    where
        K: DatabaseKey + DatabaseRecord,
    {
        if <K as DatabaseKey>::NOTIFY_ON_MODIFY {
            self.isolated_tx
                .add_notification_key(&key.to_bytes())
                .expect("Notifications not setup properly")
        }
    }

    #[instrument(level = "debug", skip_all, fields(?key, ?value), ret)]
    pub async fn insert_entry<K>(&mut self, key: &K, value: &K::Value) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        self.add_notification_key(key);
        self.isolated_tx
            .raw_insert_bytes(&key.to_bytes(), &value.to_bytes())
            .await
            .expect("Unrecoverable error while inserting into the database")
            .map(|old_val_bytes| {
                decode_value(&old_val_bytes, self.decoders)
                    .expect("Unrecoverable error while decoding the database value")
            })
    }

    #[instrument(level = "debug", skip_all, fields(?key, ?value), ret)]
    pub async fn insert_new_entry<K>(&mut self, key: &K, value: &K::Value)
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        self.add_notification_key(key);
        let key_bytes = key.to_bytes();
        let value_bytes = value.to_bytes();
        let prev_val = self
            .isolated_tx
            .raw_insert_bytes(&key_bytes, &value_bytes)
            .await
            .expect("Unrecoverable error occurred while inserting new entry into database");
        if let Some(prev_val) = prev_val {
            warn!(
                target: LOG_DB,
                key = %AbbreviateHexBytes(&key_bytes),
                prev_value = %AbbreviateHexBytes(&prev_val),
                "Database overwriting element when expecting insertion of new entry.",
            );
        }
    }

    #[instrument(level = "debug", skip_all, fields(?key, ret), ret)]
    pub async fn remove_entry<K>(&mut self, key: &K) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        self.add_notification_key(key);
        let key_bytes = key.to_bytes();
        match self
            .isolated_tx
            .raw_remove_entry(&key_bytes)
            .await
            .expect("Unrecoverable error occurred while removing an entry from the database")
        {
            Some(value) => Some(
                K::Value::from_bytes(&value, self.decoders)
                    .expect("Unrecoverable error when decoding the database value"),
            ),
            None => None,
        }
    }

    #[instrument(level = "debug", skip_all, fields(key = ?key_prefix), ret)]
    pub async fn remove_by_prefix<KP>(&mut self, key_prefix: &KP)
    where
        KP: DatabaseLookup,
    {
        self.commit_tracker.has_writes = true;
        self.isolated_tx
            .raw_remove_by_prefix(&key_prefix.to_bytes())
            .await
            .expect("Unrecoverable error occurred while removing by prefix");
    }
}

/// IsolatedDatabaseTransaction is a private wrapper around
/// ISingleUseDatabaseTransaction that is responsible for inserting and striping
/// prefixes before reading or writing to the database. It does this by
/// implementing ISingleUseDatabaseTransaction and manipulating the prefix bytes
/// in the raw insert/get functions. This is done to isolate modules/module
/// instances from each other inside the database, which allows the same module
/// to be instantiated twice or two different modules to use the same key.
struct IsolatedDatabaseTransaction<
    'isolated,
    'parent: 'isolated,
    T: MaybeSend + Encodable + 'isolated,
> {
    inner_tx: &'isolated mut dyn ISingleUseDatabaseTransaction<'parent>,
    prefix: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<'isolated, 'parent: 'isolated, T: MaybeSend + Encodable>
    IsolatedDatabaseTransaction<'isolated, 'parent, T>
{
    pub fn new(
        dbtx: &'isolated mut dyn ISingleUseDatabaseTransaction<'parent>,
        module_prefix: Option<&T>,
    ) -> IsolatedDatabaseTransaction<'isolated, 'parent, T> {
        let mut prefix_bytes = vec![];
        if let Some(module_prefix) = module_prefix {
            prefix_bytes = Self::prefix_with_module(module_prefix);
        }

        IsolatedDatabaseTransaction {
            inner_tx: dbtx,
            prefix: prefix_bytes,
            _marker: PhantomData::<T>,
        }
    }

    fn prefix_with_module(module_prefix: &T) -> Vec<u8> {
        let mut prefix_bytes = vec![MODULE_GLOBAL_PREFIX];
        module_prefix
            .consensus_encode(&mut prefix_bytes)
            .expect("Error encoding module instance id as prefix");
        prefix_bytes
    }

    // Yes, this could be proper method receiving self but it's hard to return a
    // stream and satisfy the borrow checker if this struct is short lived
    async fn raw_find_by_prefix(
        mut prefix_with_module: Vec<u8>,
        dbtx: &'isolated mut dyn ISingleUseDatabaseTransaction<'parent>,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'isolated>> {
        let original_prefix_len = prefix_with_module.len();
        prefix_with_module.extend_from_slice(key_prefix);
        let raw_prefix = dbtx
            .raw_find_by_prefix(prefix_with_module.as_slice())
            .await?;

        Ok(Box::pin(raw_prefix.map(move |(key, value)| {
            let stripped_key = &key[original_prefix_len..];
            (stripped_key.to_vec(), value)
        })))
    }

    async fn raw_find_by_prefix_sorted_descending(
        mut prefix_with_module: Vec<u8>,
        dbtx: &'isolated mut dyn ISingleUseDatabaseTransaction<'parent>,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'isolated>> {
        let original_prefix_len = prefix_with_module.len();
        prefix_with_module.extend_from_slice(key_prefix);
        let raw_prefix = dbtx
            .raw_find_by_prefix_sorted_descending(prefix_with_module.as_slice())
            .await?;

        Ok(Box::pin(raw_prefix.map(move |(key, value)| {
            let stripped_key = &key[original_prefix_len..];
            (stripped_key.to_vec(), value)
        })))
    }
}

#[apply(async_trait_maybe_send!)]
impl<'isolated, 'parent, T: MaybeSend + Encodable + 'isolated>
    ISingleUseDatabaseTransaction<'isolated>
    for IsolatedDatabaseTransaction<'isolated, 'parent, T>
{
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut key_with_prefix = self.prefix.clone();
        key_with_prefix.extend_from_slice(key);
        self.inner_tx
            .raw_insert_bytes(key_with_prefix.as_slice(), value)
            .await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut key_with_prefix = self.prefix.clone();
        key_with_prefix.extend_from_slice(key);
        self.inner_tx
            .raw_get_bytes(key_with_prefix.as_slice())
            .await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut key_with_prefix = self.prefix.clone();
        key_with_prefix.extend_from_slice(key);
        self.inner_tx
            .raw_remove_entry(key_with_prefix.as_slice())
            .await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        IsolatedDatabaseTransaction::<T>::raw_find_by_prefix(
            self.prefix.clone(),
            self.inner_tx,
            key_prefix,
        )
        .await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        IsolatedDatabaseTransaction::<T>::raw_find_by_prefix_sorted_descending(
            self.prefix.clone(),
            self.inner_tx,
            key_prefix,
        )
        .await
    }

    async fn raw_remove_by_prefix(&mut self, key: &[u8]) -> Result<()> {
        let mut key_with_prefix = self.prefix.clone();
        key_with_prefix.extend_from_slice(key);
        self.inner_tx.raw_remove_by_prefix(&key_with_prefix).await
    }

    async fn commit_tx(&mut self) -> Result<()> {
        panic!("DatabaseTransaction inside modules cannot be committed");
    }

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        self.inner_tx.rollback_tx_to_savepoint().await
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        self.inner_tx.set_tx_savepoint().await
    }

    fn add_notification_key(&mut self, key: &[u8]) -> Result<()> {
        let mut key_with_module = self.prefix.clone();
        key_with_module.extend_from_slice(key);
        self.inner_tx.add_notification_key(&key_with_module)
    }
}

/// `DatabaseTransaction` is the parent-level database transaction that can
/// modify the database. The owner of the `DatabaseTransaction` is responsible
/// for managing the lifetime of the `DatabaseTransaction`, either by committing
/// the modifications to the database or rolling back the transaction. From this
/// parent-level `DatabaseTransaction`, a `ModuleDatabaseTransaction`
/// can be created which operates like a child transaction where the child
/// transaction only has access to the modules database namespace.
///
/// `DatabaseTransaction` is intended to be used for atomic database operations
/// that span across modules.
#[doc = " A handle to a type-erased database implementation"]
pub struct DatabaseTransaction<'a> {
    tx: Box<dyn ISingleUseDatabaseTransaction<'a>>,
    decoders: ModuleDecoderRegistry,
    commit_tracker: CommitTracker,
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

impl<'parent> DatabaseTransaction<'parent> {
    pub fn new(
        dbtx: Box<dyn ISingleUseDatabaseTransaction<'parent>>,
        decoders: ModuleDecoderRegistry,
        notifications: &'parent Notifications,
    ) -> DatabaseTransaction<'parent> {
        DatabaseTransaction {
            tx: Box::new(NotifyingTransaction::new(dbtx, notifications)),
            decoders,
            commit_tracker: CommitTracker {
                is_committed: false,
                has_writes: false,
            },
        }
    }

    pub fn with_module_prefix(
        &mut self,
        module_instance_id: ModuleInstanceId,
    ) -> ModuleDatabaseTransaction<'_> {
        ModuleDatabaseTransaction::new(
            self.tx.as_mut(),
            Some(&module_instance_id),
            &self.decoders,
            &mut self.commit_tracker,
        )
    }

    pub fn get_isolated(&mut self) -> ModuleDatabaseTransaction<'_> {
        ModuleDatabaseTransaction::new(
            self.tx.as_mut(),
            None,
            &self.decoders,
            &mut self.commit_tracker,
        )
    }

    pub fn new_module_tx(
        self,
        module_instance_id: ModuleInstanceId,
    ) -> DatabaseTransaction<'parent> {
        let decoders = self.decoders.clone();
        let commit_tracker = self.commit_tracker.clone();
        let single_use = CommittableIsolatedDatabaseTransaction::new(self.tx, module_instance_id);
        DatabaseTransaction {
            tx: Box::new(single_use),
            decoders,
            commit_tracker,
        }
    }

    pub async fn commit_tx_result(mut self) -> Result<()> {
        self.commit_tracker.is_committed = true;
        return self.tx.commit_tx().await;
    }

    pub async fn commit_tx(mut self) {
        self.commit_tracker.is_committed = true;
        self.tx
            .commit_tx()
            .await
            .expect("Unrecoverable error occurred while committing to the database.");
    }

    #[instrument(level = "debug", skip_all, fields(?key))]
    pub async fn get_value<K>(&mut self, key: &K) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = self
            .tx
            .raw_get_bytes(&key_bytes)
            .await
            .expect("Unrecoverable error when reading from database");
        match value_bytes {
            Some(value_bytes) => Some(
                decode_value::<K::Value>(&value_bytes, &self.decoders)
                    .expect("Unrecoverable error when decoding the database value"),
            ),
            None => None,
        }
    }

    #[instrument(level = "debug", skip_all, fields(key = ?key_prefix))]
    pub async fn find_by_prefix<KP>(
        &mut self,
        key_prefix: &KP,
    ) -> impl Stream<
        Item = (
            KP::Record,
            <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value,
        ),
    > + '_
    where
        KP: DatabaseLookup,
        KP::Record: DatabaseKey,
    {
        debug!("find by prefix");
        let decoders = self.decoders.clone();
        let prefix_bytes = key_prefix.to_bytes();
        self.tx
            .raw_find_by_prefix(&prefix_bytes)
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

    #[instrument(level = "debug", skip_all, fields(key = ?key_prefix))]
    pub async fn find_by_prefix_sorted_descending<KP>(
        &mut self,
        key_prefix: &KP,
    ) -> impl Stream<
        Item = (
            KP::Record,
            <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value,
        ),
    > + '_
    where
        KP: DatabaseLookup,
        KP::Record: DatabaseKey,
    {
        find_by_prefix_sorted_descending(self.tx.as_mut(), self.decoders.clone(), key_prefix).await
    }

    #[instrument(level = "debug", skip_all, fields(?key, ?value), ret)]
    pub async fn insert_entry<K>(&mut self, key: &K, value: &K::Value) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        self.add_notification_key(key);
        self.tx
            .raw_insert_bytes(&key.to_bytes(), &value.to_bytes())
            .await
            .expect("Unrecoverable error while inserting into the database")
            .map(|old_val_bytes| {
                decode_value(&old_val_bytes, &self.decoders)
                    .expect("Unrecoverable error while decoding the database value")
            })
    }

    #[instrument(level = "debug", skip_all, fields(?key, ?value), ret)]
    pub async fn insert_new_entry<K>(&mut self, key: &K, value: &K::Value)
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        self.add_notification_key(key);
        let prev_val = self
            .tx
            .raw_insert_bytes(&key.to_bytes(), &value.to_bytes())
            .await
            .expect("Unrecoverable error occurred while inserting new entry into database");
        if let Some(prev_val) = prev_val {
            warn!(
                target: LOG_DB,
                "Database overwriting element when expecting insertion of new entry. Key: {:?} Prev Value: {:?}",
                key,
                prev_val,
            );
        }
    }

    #[instrument(level = "debug", skip_all, fields(?key))]
    fn add_notification_key<K>(&mut self, key: &K)
    where
        K: DatabaseKey + DatabaseRecord,
    {
        if <K as DatabaseKey>::NOTIFY_ON_MODIFY {
            self.tx
                .add_notification_key(&key.to_bytes())
                .expect("Notifications not setup properly")
        }
    }

    #[instrument(level = "debug", skip_all, fields(?key, ret), ret)]
    pub async fn remove_entry<K>(&mut self, key: &K) -> Option<K::Value>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        self.add_notification_key(key);
        let key_bytes = key.to_bytes();
        match self
            .tx
            .raw_remove_entry(&key_bytes)
            .await
            .expect("Unrecoverable error occurred while removing an entry from the database")
        {
            Some(value) => Some(
                K::Value::from_bytes(&value, &self.decoders)
                    .expect("Unrecoverable error occurred while decoding the database value"),
            ),
            None => None,
        }
    }

    #[instrument(level = "debug", skip_all, fields(key = ?key_prefix), ret)]
    pub async fn remove_by_prefix<KP>(&mut self, key_prefix: &KP)
    where
        KP: DatabaseLookup,
    {
        self.commit_tracker.has_writes = true;
        self.tx
            .raw_remove_by_prefix(&key_prefix.to_bytes())
            .await
            .expect("Unrecoverable error occurred while removing by prefix");
    }

    #[instrument(level = "debug", skip_all, ret)]
    pub async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        self.tx.rollback_tx_to_savepoint().await
    }

    #[instrument(level = "debug", skip_all, ret)]
    pub async fn set_tx_savepoint(&mut self) -> Result<()> {
        self.tx.set_tx_savepoint().await
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
        let db_items = $dbtx
            .find_by_prefix(&$prefix_type)
            .await
            .map(|(key, val)| {
                (
                    $crate::encoding::Encodable::consensus_encode_to_hex(&key).expect("can't fail"),
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
        let db_items = $dbtx
            .find_by_prefix(&$prefix_type)
            .await
            .map(|(key, val)| {
                (
                    $crate::encoding::Encodable::consensus_encode_to_hex(&key).expect("can't fail"),
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
        let db_items = $dbtx
            .find_by_prefix(&$prefix_type)
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
pub type MigrationMap<'a> = BTreeMap<
    DatabaseVersion,
    for<'b> fn(
        &'b mut DatabaseTransaction<'a>,
    ) -> Pin<Box<dyn futures::Future<Output = anyhow::Result<()>> + Send + 'b>>,
>;

/// `apply_migrations` iterates from the on disk database version for the module
/// up to `target_db_version` and executes all of the migrations that exist in
/// the `MigrationMap`. Each migration in `MigrationMap` updates the database to
/// have the correct on-disk structures that the code is expecting. The entire
/// migration process is atomic (i.e migration from 0->1 and 1->2 happen
/// atomically). This function is called before the module is initialized and as
/// long as the correct migrations are supplied in `MigrationMap`, the module
/// will be able to read and write from the database successfully.
pub async fn apply_migrations<'a>(
    db: &'a Database,
    kind: String,
    target_db_version: DatabaseVersion,
    migrations: MigrationMap<'a>,
) -> Result<(), anyhow::Error> {
    let mut dbtx = db.begin_transaction().await;
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
                migration(&mut dbtx).await?;
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
            let mut test_module_dbtx = test_dbtx.with_module_prefix(TEST_MODULE_PREFIX);

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
            let mut alt_module_dbtx = alt_dbtx.with_module_prefix(ALT_MODULE_PREFIX);

            alt_module_dbtx
                .insert_entry(&TestKey(100), &TestVal(103))
                .await;

            alt_module_dbtx
                .insert_entry(&TestKey(101), &TestVal(104))
                .await;
        }

        alt_dbtx.commit_tx().await;

        // verfiy test_module_dbtx can only see key/value pairs from its own module
        let mut test_dbtx = db.begin_transaction().await;
        let mut test_module_dbtx = test_dbtx.with_module_prefix(TEST_MODULE_PREFIX);
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
            AutocommitError, IDatabase, IDatabaseTransaction, ISingleUseDatabaseTransaction,
            SingleUseDatabaseTransaction,
        };
        use crate::ModuleDecoderRegistry;

        #[derive(Debug)]
        struct FakeDatabase;

        #[async_trait]
        impl IDatabase for FakeDatabase {
            async fn begin_transaction<'a>(&'a self) -> Box<dyn ISingleUseDatabaseTransaction<'a>> {
                let single_use = SingleUseDatabaseTransaction::new(FakeTransaction(PhantomData));
                Box::new(single_use)
            }
        }

        #[derive(Debug)]
        struct FakeTransaction<'a>(PhantomData<&'a ()>);

        #[async_trait]
        impl<'a> IDatabaseTransaction<'a> for FakeTransaction<'a> {
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

            async fn raw_find_by_prefix_sorted_descending(
                &mut self,
                _key_prefix: &[u8],
            ) -> anyhow::Result<crate::db::PrefixStream<'_>> {
                unimplemented!()
            }

            async fn commit_tx(self) -> anyhow::Result<()> {
                Err(anyhow!("Can't commit!"))
            }

            async fn rollback_tx_to_savepoint(&mut self) {
                unimplemented!()
            }

            async fn set_tx_savepoint(&mut self) {
                unimplemented!()
            }
        }

        let db = Database::new(FakeDatabase, ModuleDecoderRegistry::default());
        let err = db
            .autocommit::<_, _, ()>(|_dbtx| Box::pin(async { Ok(()) }), Some(5))
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
    tx: &'r mut dyn ISingleUseDatabaseTransaction<'inner>,
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

    async fn waiter(db: &Database, key: TestKey) -> tokio::task::JoinHandle<TestVal> {
        let db = db.clone();
        let (tx, rx) = oneshot::channel::<()>();
        let join_handle = tokio::spawn(async move {
            let sub = db.wait_key_exists(&key);
            tx.send(()).unwrap();
            sub.await
        });
        rx.await.unwrap();
        join_handle
    }

    #[tokio::test]
    async fn test_wait_key_before_transaction() {
        let key = TestKey(1);
        let val = TestVal(2);
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

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
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

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
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

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
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

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
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let db = db.new_isolated(module_instance_id);

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
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

        let key_task = waiter(&db.new_isolated(module_instance_id), TestKey(1)).await;

        let mut tx = db.begin_transaction().await;
        let mut tx_mod = tx.with_module_prefix(module_instance_id);
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
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

        let key_task = waiter(&db, TestKey(1)).await;
        assert_eq!(
            future_returns_shortly(async { key_task.await.unwrap() }).await,
            None,
            "should not notify"
        );
    }
}
