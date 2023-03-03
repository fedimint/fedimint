use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result};
use fedimint_logging::LOG_DB;
use futures::future::BoxFuture;
use futures::{stream, Stream, StreamExt};
use macro_rules_attribute::apply;
use serde::Serialize;
use strum_macros::EnumIter;
use thiserror::Error;
use tracing::{debug, info, instrument, trace, warn};

use crate::core::ModuleInstanceId;
use crate::encoding::{Decodable, Encodable};
use crate::fmt_utils::AbbreviateHexBytes;
use crate::task::{MaybeSend, MaybeSync};
use crate::{async_trait_maybe_send, maybe_add_send};

pub mod mem_impl;

pub use tests::*;

use crate::module::registry::ModuleDecoderRegistry;

pub const MODULE_GLOBAL_PREFIX: u8 = 0xff;

pub trait DatabaseKeyPrefix: Debug {
    fn to_bytes(&self) -> Vec<u8>;
}

/// A key + value pair in the database with a unique prefix
/// Extends `DatabaseKeyPrefix` to prepend the key's prefix.
pub trait DatabaseRecord: DatabaseKeyPrefix {
    const DB_PREFIX: u8;
    type Key: DatabaseKey + Debug;
    type Value: DatabaseValue + Debug;
}

/// A key that can be used to query one or more `DatabaseRecord`
/// Extends `DatabaseKeyPrefix` to prepend the key's prefix.
pub trait DatabaseLookup: DatabaseKeyPrefix {
    type Record: DatabaseRecord;
    type Key: DatabaseKey + Debug;
}

// Every `DatabaseRecord` is automatically a `DatabaseLookup`
impl<Record> DatabaseLookup for Record
where
    Record: DatabaseRecord + Debug + Decodable + Encodable,
{
    type Record = Record;
    type Key = Record;
}

/// `DatabaseKey` that represents the lookup structure for retrieving key/value
/// pairs from the database.
pub trait DatabaseKey: Sized {
    fn from_bytes(data: &[u8], modules: &ModuleDecoderRegistry) -> Result<Self, DecodingError>;
}

/// `DatabaseValue` that represents the value structure of database records.
pub trait DatabaseValue: Sized + Debug {
    fn from_bytes(data: &[u8], modules: &ModuleDecoderRegistry) -> Result<Self, DecodingError>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub type PrefixStream<'a> = Pin<Box<maybe_add_send!(dyn Stream<Item = (Vec<u8>, Vec<u8>)> + 'a)>>;

#[apply(async_trait_maybe_send!)]
pub trait IDatabase: Debug + MaybeSend + MaybeSync {
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
    module_decoders: ModuleDecoderRegistry,
    db: Db,
}

/// Error returned when the autocommit function fails
#[derive(Debug, Error)]
pub enum AutocommitError<E> {
    /// Committing the transaction failed too many times, giving up
    CommitFailed {
        /// Number of retries
        retries: usize,
        /// Last error on commit
        last_error: anyhow::Error,
    },
    /// Error returned by the closure provided to `autocommit`. If returned no
    /// commit was attempted in that round
    ClosureError {
        /// Retry on which the closure returned an error
        ///
        /// Values other than 0 typically indicate a logic error since the
        /// closure given to `autocommit` should not have side effects
        /// and thus keep succeeding if it succeeded once.
        retries: usize,
        /// Error returned by the closure
        error: E,
    },
}

impl Database {
    pub fn new(db: impl IDatabase + 'static, module_decoders: ModuleDecoderRegistry) -> Self {
        let inner = DatabaseInner {
            db,
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
        );

        match self.module_instance_id {
            Some(module_instance_id) => dbtx.new_module_tx(module_instance_id),
            None => dbtx,
        }
    }

    /// Runs a closure with a reference to a database transaction and tries to
    /// commit the transaction if the closure returns `Ok` and rolls it back
    /// otherwise. If committing fails the closure is run again for up to
    /// `max_retries` times. If `max_retries` is `None` it will run
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
    pub async fn autocommit<'s: 'dt, 'dt, F, T, E>(
        &'s self,
        tx_fn: F,
        max_retries: Option<usize>,
    ) -> Result<T, AutocommitError<E>>
    where
        for<'a> F: Fn(&'a mut DatabaseTransaction<'dt>) -> BoxFuture<'a, Result<T, E>>,
    {
        let mut retries: usize = 0;
        loop {
            let mut dbtx = self.begin_transaction().await;

            match tx_fn(&mut dbtx).await {
                Ok(val) => {
                    match dbtx.commit_tx().await {
                        Ok(()) => {
                            return Ok(val);
                        }
                        Err(e) if max_retries.map(|mr| mr <= retries).unwrap_or(false) => {
                            return Err(AutocommitError::CommitFailed {
                                retries,
                                last_error: e,
                            });
                        }
                        Err(_) => {
                            // try again
                        }
                    }
                }
                Err(e) => {
                    return Err(AutocommitError::ClosureError { retries, error: e });
                }
            };

            // The `checked_add()` function is used to catch the `usize` overflow.
            // With `usize=32bit` and an assumed time of 1ms per iteration, this would crash
            // after ~50 days. But if that's the case, something else must be wrong.
            // With `usize=64bit` it would take much longer, obviously.
            retries = retries
                .checked_add(1)
                .expect("db autocommit retry counter overflowed");
        } // end of loop
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
/// following anamolies:
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
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>>;

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> PrefixStream<'_>;

    /// Default implementation is a combination of [`Self::raw_find_by_prefix`]
    /// + loop over [`Self::raw_remove_entry`]
    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        let keys = self
            .raw_find_by_prefix(key_prefix)
            .await
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
}

/// `ISingleUseDatabaseTransaction` re-defines the functions from
/// `IDatabaseTransaction` but does not consumed `self` when committing to the
/// database. This allows for wrapper structs to more easily borrow
/// `ISingleUseDatabaseTransaction` without needing to make additional
/// allocations.
#[apply(async_trait_maybe_send!)]
pub trait ISingleUseDatabaseTransaction<'a>: 'a + Send {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>>;

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>>;

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()>;

    async fn commit_tx(&mut self) -> Result<()>;

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()>;

    async fn set_tx_savepoint(&mut self) -> Result<()>;
}

/// Struct that implements `ISingleUseDatabaseTransaction` and can be wrapped
/// easier in other structs since it does not consumed `self` by move.
pub struct SingleUseDatabaseTransaction<'a, Tx: IDatabaseTransaction<'a> + Send>(
    Option<Tx>,
    &'a PhantomData<()>,
);

impl<'a, Tx: IDatabaseTransaction<'a> + Send> SingleUseDatabaseTransaction<'a, Tx> {
    pub fn new(dbtx: Tx) -> SingleUseDatabaseTransaction<'a, Tx> {
        SingleUseDatabaseTransaction(Some(dbtx), &PhantomData)
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a, Tx: IDatabaseTransaction<'a> + Send> ISingleUseDatabaseTransaction<'a>
    for SingleUseDatabaseTransaction<'a, Tx>
{
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
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
        Ok(self
            .0
            .as_mut()
            .context("Cannot retreive from already consumed transaction")?
            .raw_find_by_prefix(key_prefix)
            .await)
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

/// `ModuleDatabaseTransaction` is an isolated database transaction that
/// consumes an existing `DatabaseTransaction`. Unlike
/// `IsolatedDatabaseTransaction`, `ModuleDatabaseTransaction` can be owned by
/// the module as long as it has a handle to the isolated `Database`. This
/// allows the module to make changes only affecting it's own portion of the
/// database and also being able to commit those changes. From the module's
/// perspective, the `Database` is isolated and calling `begin_transaction` will
/// always produce a `ModuleDatabaseTransaction`, which is isolated from other
/// modules by prepending a prefix to each key.
struct ModuleDatabaseTransaction<'a> {
    dbtx: Box<dyn ISingleUseDatabaseTransaction<'a>>,
    prefix: ModuleInstanceId,
    decoders: ModuleDecoderRegistry,
    commit_tracker: CommitTracker,
}

impl<'a> ModuleDatabaseTransaction<'a> {
    pub fn new(
        dbtx: Box<dyn ISingleUseDatabaseTransaction<'a>>,
        prefix: ModuleInstanceId,
        decoders: ModuleDecoderRegistry,
        commit_tracker: CommitTracker,
    ) -> ModuleDatabaseTransaction<'a> {
        ModuleDatabaseTransaction {
            dbtx,
            prefix,
            decoders,
            commit_tracker,
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a> ISingleUseDatabaseTransaction<'a> for ModuleDatabaseTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let mut isolated = IsolatedDatabaseTransaction::new(
            self.dbtx.as_mut(),
            Some(self.prefix),
            &self.decoders,
            &mut self.commit_tracker,
        );
        isolated.raw_insert_bytes(key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut isolated = IsolatedDatabaseTransaction::new(
            self.dbtx.as_mut(),
            Some(self.prefix),
            &self.decoders,
            &mut self.commit_tracker,
        );
        isolated.raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut isolated = IsolatedDatabaseTransaction::new(
            self.dbtx.as_mut(),
            Some(self.prefix),
            &self.decoders,
            &mut self.commit_tracker,
        );
        isolated.raw_remove_entry(key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        let mut isolated = IsolatedDatabaseTransaction::new(
            self.dbtx.as_mut(),
            Some(self.prefix),
            &self.decoders,
            &mut self.commit_tracker,
        );
        let stream = isolated
            .raw_find_by_prefix(key_prefix)
            .await?
            .collect::<Vec<_>>()
            .await;
        Ok(Box::pin(stream::iter(stream)))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        let mut isolated = IsolatedDatabaseTransaction::new(
            self.dbtx.as_mut(),
            Some(self.prefix),
            &self.decoders,
            &mut self.commit_tracker,
        );
        isolated.raw_remove_by_prefix(key_prefix).await
    }

    async fn commit_tx(&mut self) -> Result<()> {
        self.dbtx.commit_tx().await
    }

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        let mut isolated = IsolatedDatabaseTransaction::new(
            self.dbtx.as_mut(),
            Some(self.prefix),
            &self.decoders,
            &mut self.commit_tracker,
        );
        isolated.rollback_tx_to_savepoint().await
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        let mut isolated = IsolatedDatabaseTransaction::new(
            self.dbtx.as_mut(),
            Some(self.prefix),
            &self.decoders,
            &mut self.commit_tracker,
        );
        isolated.set_tx_savepoint().await
    }
}

/// IsolatedDatabaseTransaction is a wrapper around DatabaseTransaction that is
/// responsible for inserting and striping prefixes before reading or writing to
/// the database. It does this by implementing IDatabaseTransaction and
/// manipulating the prefix bytes in the raw insert/get functions. This is done
/// to isolate modules/module instances from each other inside the database,
/// which allows the same module to be instantiated twice or two different
/// modules to use the same key.
pub struct IsolatedDatabaseTransaction<
    'isolated,
    'parent: 'isolated,
    T: Send + Encodable + 'isolated,
> {
    inner_tx: &'isolated mut dyn ISingleUseDatabaseTransaction<'parent>,
    prefix: Vec<u8>,
    decoders: &'isolated ModuleDecoderRegistry,
    commit_tracker: &'isolated mut CommitTracker,
    _marker: PhantomData<T>,
}

impl<'isolated, 'parent: 'isolated, T: Send + Encodable>
    IsolatedDatabaseTransaction<'isolated, 'parent, T>
{
    pub fn new(
        dbtx: &'isolated mut dyn ISingleUseDatabaseTransaction<'parent>,
        module_prefix: Option<T>,
        decoders: &'isolated ModuleDecoderRegistry,
        commit_tracker: &'isolated mut CommitTracker,
    ) -> IsolatedDatabaseTransaction<'isolated, 'parent, T> {
        let mut prefix_bytes = vec![];
        if let Some(module_prefix) = module_prefix {
            prefix_bytes = vec![MODULE_GLOBAL_PREFIX];
            module_prefix
                .consensus_encode(&mut prefix_bytes)
                .expect("Error encoding module instance id as prefix");
        }

        IsolatedDatabaseTransaction {
            inner_tx: dbtx,
            prefix: prefix_bytes,
            _marker: PhantomData::<T>,
            decoders,
            commit_tracker,
        }
    }

    #[instrument(level = "debug", skip_all, fields(?key), ret)]
    pub async fn get_value<K>(&mut self, key: &K) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_get_bytes(&key_bytes).await? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(decode_value::<K::Value>(&value_bytes, self.decoders)?))
    }

    #[instrument(level = "debug", skip_all, fields(key = ?key_prefix))]
    pub async fn find_by_prefix<KP>(
        &mut self,
        key_prefix: &KP,
    ) -> impl Stream<
        Item = Result<(
            KP::Key,
            <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value,
        )>,
    > + '_
    where
        KP: DatabaseLookup,
    {
        debug!("find by prefix");
        let decoders = self.decoders.clone();
        let prefix_bytes = key_prefix.to_bytes();
        self.raw_find_by_prefix(&prefix_bytes)
            .await
            .expect("Error doing prefix search in database")
            .map(move |(key_bytes, value_bytes)| {
                let key = KP::Key::from_bytes(&key_bytes, &decoders)?;
                let value = decode_value(&value_bytes, &decoders)?;
                Ok((key, value))
            })
    }

    #[instrument(level = "debug", skip_all, fields(?key, ?value), ret)]
    pub async fn insert_entry<K>(&mut self, key: &K, value: &K::Value) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        match self
            .raw_insert_bytes(&key.to_bytes(), value.to_bytes())
            .await?
        {
            Some(old_val_bytes) => Ok(Some(decode_value(&old_val_bytes, self.decoders)?)),
            None => Ok(None),
        }
    }

    #[instrument(level = "debug", skip_all, fields(?key, ?value), ret)]
    pub async fn insert_new_entry<K>(
        &mut self,
        key: &K,
        value: &K::Value,
    ) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        match self
            .raw_insert_bytes(&key.to_bytes(), value.to_bytes())
            .await?
        {
            Some(_) => {
                warn!(
                    target: LOG_DB,
                    "Database overwriting element when expecting insertion of new entry. Key: {:?}",
                    key
                );
                Ok(None)
            }
            None => Ok(None),
        }
    }

    #[instrument(level = "debug", skip_all, fields(?key, ret), ret)]
    pub async fn remove_entry<K>(&mut self, key: &K) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_remove_entry(&key_bytes).await? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(K::Value::from_bytes(&value_bytes, self.decoders)?))
    }

    #[instrument(level = "debug", skip_all, fields(key = ?key_prefix), ret)]
    pub async fn remove_by_prefix<KP>(&mut self, key_prefix: &KP) -> Result<()>
    where
        KP: DatabaseLookup,
    {
        self.commit_tracker.has_writes = true;
        self.raw_remove_by_prefix(&key_prefix.to_bytes()).await
    }
}

#[apply(async_trait_maybe_send!)]
impl<'isolated, 'parent, T: Send + Encodable + 'isolated> ISingleUseDatabaseTransaction<'isolated>
    for IsolatedDatabaseTransaction<'isolated, 'parent, T>
{
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
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
        let mut prefix_with_module = self.prefix.clone();
        prefix_with_module.extend_from_slice(key_prefix);
        let raw_prefix = self
            .inner_tx
            .raw_find_by_prefix(prefix_with_module.as_slice())
            .await?;

        Ok(Box::pin(raw_prefix.map(|kv| {
            let key = kv.0;
            let stripped_key = &key[(self.prefix.len())..];
            (stripped_key.to_vec(), kv.1)
        })))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        self.inner_tx.raw_remove_by_prefix(key_prefix).await
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
}

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
    ) -> DatabaseTransaction<'parent> {
        DatabaseTransaction {
            tx: dbtx,
            decoders,
            commit_tracker: CommitTracker {
                is_committed: false,
                has_writes: false,
            },
        }
    }

    pub fn with_module_prefix<'isolated>(
        &'isolated mut self,
        module_instance_id: ModuleInstanceId,
    ) -> IsolatedDatabaseTransaction<'isolated, 'parent, ModuleInstanceId>
    where
        'parent: 'isolated,
    {
        IsolatedDatabaseTransaction::new(
            self.tx.as_mut(),
            Some(module_instance_id),
            &self.decoders,
            &mut self.commit_tracker,
        )
    }

    pub fn get_isolated<'isolated>(
        &'isolated mut self,
    ) -> IsolatedDatabaseTransaction<'isolated, 'parent, ModuleInstanceId> {
        IsolatedDatabaseTransaction::new(
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
        let single_use = ModuleDatabaseTransaction::new(
            self.tx,
            module_instance_id,
            self.decoders,
            self.commit_tracker,
        );
        DatabaseTransaction {
            tx: Box::new(single_use),
            decoders,
            commit_tracker,
        }
    }

    pub async fn commit_tx(mut self) -> Result<()> {
        self.commit_tracker.is_committed = true;
        return self.tx.commit_tx().await;
    }

    #[instrument(level = "debug", skip_all, fields(?key), ret)]
    pub async fn get_value<K>(&mut self, key: &K) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.tx.raw_get_bytes(&key_bytes).await? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(decode_value::<K::Value>(
            &value_bytes,
            &self.decoders,
        )?))
    }

    #[instrument(level = "debug", skip_all, fields(key = ?key_prefix))]
    pub async fn find_by_prefix<KP>(
        &mut self,
        key_prefix: &KP,
    ) -> impl Stream<
        Item = Result<(
            KP::Key,
            <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value,
        )>,
    > + '_
    where
        KP: DatabaseLookup,
    {
        debug!("find by prefix");
        let decoders = self.decoders.clone();
        let prefix_bytes = key_prefix.to_bytes();
        self.tx
            .raw_find_by_prefix(&prefix_bytes)
            .await
            .expect("Error doing prefix search in database")
            .map(move |(key_bytes, value_bytes)| {
                let key = KP::Key::from_bytes(&key_bytes, &decoders)?;
                let value = decode_value(&value_bytes, &decoders)?;
                Ok((key, value))
            })
    }

    #[instrument(level = "debug", skip_all, fields(?key, ?value), ret)]
    pub async fn insert_entry<K>(&mut self, key: &K, value: &K::Value) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        match self
            .tx
            .raw_insert_bytes(&key.to_bytes(), value.to_bytes())
            .await?
        {
            Some(old_val_bytes) => Ok(Some(decode_value(&old_val_bytes, &self.decoders)?)),
            None => Ok(None),
        }
    }

    #[instrument(level = "debug", skip_all, fields(?key, ?value), ret)]
    pub async fn insert_new_entry<K>(
        &mut self,
        key: &K,
        value: &K::Value,
    ) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        match self
            .tx
            .raw_insert_bytes(&key.to_bytes(), value.to_bytes())
            .await?
        {
            Some(_) => {
                warn!(
                    target: LOG_DB,
                    "Database overwriting element when expecting insertion of new entry. Key: {:?}",
                    key
                );
                Ok(None)
            }
            None => Ok(None),
        }
    }

    #[instrument(level = "debug", skip_all, fields(?key, ret), ret)]
    pub async fn remove_entry<K>(&mut self, key: &K) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseRecord,
    {
        self.commit_tracker.has_writes = true;
        let key_bytes = key.to_bytes();
        let value_bytes = match self.tx.raw_remove_entry(&key_bytes).await? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(K::Value::from_bytes(&value_bytes, &self.decoders)?))
    }

    #[instrument(level = "debug", skip_all, fields(key = ?key_prefix), ret)]
    pub async fn remove_by_prefix<KP>(&mut self, key_prefix: &KP) -> Result<()>
    where
        KP: DatabaseLookup,
    {
        self.commit_tracker.has_writes = true;
        self.tx.raw_remove_by_prefix(&key_prefix.to_bytes()).await
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
    (key = $key:ty, value = $val:ty, db_prefix = $db_prefix:expr $(,)?) => {
        impl $crate::db::DatabaseRecord for $key {
            const DB_PREFIX: u8 = $db_prefix as u8;
            type Key = Self;
            type Value = $val;
        }
    };
}

#[macro_export]
macro_rules! impl_db_lookup{
    (key = $key:ty $(, query_prefix = $query_prefix:ty)* $(,)?) => {
        $(
            impl $crate::db::DatabaseLookup for $query_prefix {
                type Record = $key;
                type Key = $key;
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
            .map(|res| {
                let (key, val) = res.expect("DB Error");
                (key, val)
            })
            .collect::<Vec<($key_type, $value_type)>>()
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
            .map(|res| {
                let (key, val) = res.expect("DB Error");
                (key, SerdeWrapper::from_encodable(val))
            })
            .collect::<Vec<_>>()
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
            .map(|res| {
                let (key, _) = res.expect("DB Error");
                key
            })
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
    let disk_version = dbtx.get_value(&DatabaseVersionKey).await?;
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
                .await?;
        }

        current_db_version
    } else {
        dbtx.insert_entry(&DatabaseVersionKey, &target_db_version)
            .await?;
        target_db_version
    };

    dbtx.commit_tx().await?;
    info!(target: LOG_DB, "{} module db version: {}", kind, db_version);
    Ok(())
}

#[allow(unused_imports)]
mod tests {
    use futures::{FutureExt, StreamExt};

    use super::{
        apply_migrations, Database, DatabaseTransaction, DatabaseVersion, DatabaseVersionKey,
        MigrationMap,
    };
    use crate::core::ModuleKind;
    use crate::db::mem_impl::MemDatabase;
    use crate::encoding::{Decodable, Encodable};
    use crate::module::registry::ModuleDecoderRegistry;

    #[repr(u8)]
    #[derive(Clone)]
    pub enum TestDbKeyPrefix {
        Test = 0x42,
        AltTest = 0x43,
        PercentTestKey = 0x25,
    }

    #[derive(Debug, Encodable, Decodable)]
    struct TestKey(u64);

    #[derive(Debug, Encodable, Decodable)]
    struct DbPrefixTestPrefix;

    impl_db_record!(
        key = TestKey,
        value = TestVal,
        db_prefix = TestDbKeyPrefix::Test
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

    #[derive(Debug, Encodable, Decodable)]
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
    #[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
    struct TestVal(u64);

    const TEST_MODULE_PREFIX: u16 = 1;
    const ALT_MODULE_PREFIX: u16 = 2;

    pub async fn verify_insert_elements(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        assert!(dbtx
            .insert_entry(&TestKey(1), &TestVal(2))
            .await
            .unwrap()
            .is_none());

        assert!(dbtx
            .insert_entry(&TestKey(2), &TestVal(3))
            .await
            .unwrap()
            .is_none());

        dbtx.commit_tx().await.expect("DB Error");
    }

    pub async fn verify_remove_nonexisting(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        assert_eq!(dbtx.get_value(&TestKey(1)).await.unwrap(), None);
        let removed = dbtx.remove_entry(&TestKey(1)).await;
        assert!(removed.is_ok());

        // Commit to surpress the warning message
        dbtx.commit_tx().await.expect("DB Error");
    }

    pub async fn verify_remove_existing(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        assert!(dbtx
            .insert_entry(&TestKey(1), &TestVal(2))
            .await
            .unwrap()
            .is_none());

        assert_eq!(dbtx.get_value(&TestKey(1)).await.unwrap(), Some(TestVal(2)));

        let removed = dbtx.remove_entry(&TestKey(1)).await;
        assert!(removed.is_ok());
        assert_eq!(removed.unwrap(), Some(TestVal(2)));
        assert_eq!(dbtx.get_value(&TestKey(1)).await.unwrap(), None);

        // Commit to surpress the warning message
        dbtx.commit_tx().await.expect("DB Error");
    }

    pub async fn verify_read_own_writes(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        assert!(dbtx
            .insert_entry(&TestKey(1), &TestVal(2))
            .await
            .unwrap()
            .is_none());

        assert_eq!(dbtx.get_value(&TestKey(1)).await.unwrap(), Some(TestVal(2)));

        // Commit to surpress the warning message
        dbtx.commit_tx().await.expect("DB Error");
    }

    pub async fn verify_prevent_dirty_reads(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        assert!(dbtx
            .insert_entry(&TestKey(1), &TestVal(2))
            .await
            .unwrap()
            .is_none());

        // dbtx2 should not be able to see uncommitted changes
        let mut dbtx2 = db.begin_transaction().await;
        assert_eq!(dbtx2.get_value(&TestKey(1)).await.unwrap(), None);

        // Commit to surpress the warning message
        dbtx.commit_tx().await.expect("DB Error");
    }

    pub async fn verify_find_by_prefix(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        assert!(dbtx
            .insert_entry(&TestKey(55), &TestVal(9999))
            .await
            .is_ok());
        assert!(dbtx
            .insert_entry(&TestKey(54), &TestVal(8888))
            .await
            .is_ok());

        assert!(dbtx
            .insert_entry(&AltTestKey(55), &TestVal(7777))
            .await
            .is_ok());
        assert!(dbtx
            .insert_entry(&AltTestKey(54), &TestVal(6666))
            .await
            .is_ok());
        dbtx.commit_tx().await.expect("DB Error");

        // Verify finding by prefix returns the correct set of key pairs
        let mut dbtx = db.begin_transaction().await;
        let expected_keys = 2;

        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, kv| async move {
                let (key, value) = kv.unwrap();
                match key {
                    TestKey(55) => {
                        assert!(value.eq(&TestVal(9999)));
                    }
                    TestKey(54) => {
                        assert!(value.eq(&TestVal(8888)));
                    }
                    _ => {}
                };
                returned_keys + 1
            })
            .await;

        assert_eq!(returned_keys, expected_keys);

        let expected_keys = 2;

        let returned_keys = dbtx
            .find_by_prefix(&AltDbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, kv| async move {
                let (key, value) = kv.unwrap();
                match key {
                    AltTestKey(55) => {
                        assert!(value.eq(&TestVal(7777)));
                    }
                    AltTestKey(54) => {
                        assert!(value.eq(&TestVal(6666)));
                    }
                    _ => {}
                };
                returned_keys + 1
            })
            .await;

        assert_eq!(returned_keys, expected_keys);
    }

    pub async fn verify_commit(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        assert!(dbtx
            .insert_entry(&TestKey(1), &TestVal(2))
            .await
            .unwrap()
            .is_none());
        dbtx.commit_tx().await.expect("DB Error");

        // Verify dbtx2 can see committed transactions
        let mut dbtx2 = db.begin_transaction().await;
        assert_eq!(
            dbtx2.get_value(&TestKey(1)).await.unwrap(),
            Some(TestVal(2))
        );
    }

    pub async fn verify_rollback_to_savepoint(db: Database) {
        let mut dbtx_rollback = db.begin_transaction().await;

        assert!(dbtx_rollback
            .insert_entry(&TestKey(20), &TestVal(2000))
            .await
            .is_ok());

        dbtx_rollback
            .set_tx_savepoint()
            .await
            .expect("Error setting transaction savepoint");

        assert!(dbtx_rollback
            .insert_entry(&TestKey(21), &TestVal(2001))
            .await
            .is_ok());

        assert_eq!(
            dbtx_rollback.get_value(&TestKey(20)).await.unwrap(),
            Some(TestVal(2000))
        );
        assert_eq!(
            dbtx_rollback.get_value(&TestKey(21)).await.unwrap(),
            Some(TestVal(2001))
        );

        dbtx_rollback
            .rollback_tx_to_savepoint()
            .await
            .expect("Error setting transaction savepoint");

        assert_eq!(
            dbtx_rollback.get_value(&TestKey(20)).await.unwrap(),
            Some(TestVal(2000))
        );

        assert_eq!(dbtx_rollback.get_value(&TestKey(21)).await.unwrap(), None);

        // Commit to surpress the warning message
        dbtx_rollback.commit_tx().await.expect("DB Error");
    }

    pub async fn verify_prevent_nonrepeatable_reads(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        assert_eq!(dbtx.get_value(&TestKey(100)).await.unwrap(), None);

        let mut dbtx2 = db.begin_transaction().await;

        assert!(dbtx2
            .insert_entry(&TestKey(100), &TestVal(101))
            .await
            .is_ok());

        assert_eq!(dbtx.get_value(&TestKey(100)).await.unwrap(), None);

        dbtx2.commit_tx().await.expect("DB Error");

        // dbtx should still read None because it is operating over a snapshot
        // of the data when the transaction started
        assert_eq!(dbtx.get_value(&TestKey(100)).await.unwrap(), None);

        let expected_keys = 0;
        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, kv| async move {
                let (key, value) = kv.unwrap();
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

        assert!(dbtx
            .insert_entry(&TestKey(100), &TestVal(101))
            .await
            .is_ok());

        assert!(dbtx
            .insert_entry(&TestKey(101), &TestVal(102))
            .await
            .is_ok());

        dbtx.commit_tx().await.expect("DB Error");

        let mut dbtx = db.begin_transaction().await;
        let expected_keys = 2;
        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, kv| async move {
                let (key, value) = kv.unwrap();
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

        assert!(dbtx2
            .insert_entry(&TestKey(102), &TestVal(103))
            .await
            .is_ok());

        dbtx2.commit_tx().await.expect("DB Error");

        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, kv| async move {
                let (key, value) = kv.unwrap();
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
        assert!(dbtx
            .insert_entry(&TestKey(100), &TestVal(101))
            .await
            .is_ok());
        dbtx.commit_tx().await.expect("DB Error");

        let mut dbtx2 = db.begin_transaction().await;
        let mut dbtx3 = db.begin_transaction().await;

        assert!(dbtx2
            .insert_entry(&TestKey(100), &TestVal(102))
            .await
            .is_ok());

        // Depending on if the database implementation supports optimistic or
        // pessimistic transactions, this test should generate an error here
        // (pessimistic) or at commit time (optimistic)
        let res = dbtx3
            .insert_entry(&TestKey(100), &TestVal(103))
            .await
            .is_ok();

        dbtx2.commit_tx().await.expect("DB Error");

        // We do not need to commit the second transaction if the insert failed.
        if res {
            dbtx3.commit_tx().await.expect_err("Expecting an error to be returned because this transaction is in a write-write conflict with dbtx");
        }
    }

    pub async fn verify_string_prefix(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        assert!(dbtx
            .insert_entry(&PercentTestKey(100), &TestVal(101))
            .await
            .is_ok());

        assert_eq!(
            dbtx.get_value(&PercentTestKey(100)).await.unwrap(),
            Some(TestVal(101))
        );

        assert!(dbtx
            .insert_entry(&PercentTestKey(101), &TestVal(100))
            .await
            .is_ok());

        assert!(dbtx
            .insert_entry(&PercentTestKey(101), &TestVal(100))
            .await
            .is_ok());

        assert!(dbtx
            .insert_entry(&PercentTestKey(101), &TestVal(100))
            .await
            .is_ok());

        // If the wildcard character ('%') is not handled properly, this will make
        // find_by_prefix return 5 results instead of 4
        assert!(dbtx
            .insert_entry(&TestKey(101), &TestVal(100))
            .await
            .is_ok());

        let expected_keys = 4;
        let returned_keys = dbtx
            .find_by_prefix(&PercentPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, kv| async move {
                let (key, value) = kv.unwrap();
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

        assert!(dbtx
            .insert_entry(&TestKey(100), &TestVal(101))
            .await
            .is_ok());

        assert!(dbtx
            .insert_entry(&TestKey(101), &TestVal(102))
            .await
            .is_ok());

        dbtx.commit_tx().await.expect("DB Error");

        let mut remove_dbtx = db.begin_transaction().await;
        remove_dbtx
            .remove_by_prefix(&DbPrefixTestPrefix)
            .await
            .expect("DB Error");
        remove_dbtx.commit_tx().await.expect("DB Error");

        let mut dbtx = db.begin_transaction().await;
        let expected_keys = 0;
        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, kv| async move {
                let (key, value) = kv.unwrap();
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

        assert!(dbtx
            .insert_entry(&TestKey(100), &TestVal(101))
            .await
            .is_ok());

        assert!(dbtx
            .insert_entry(&TestKey(101), &TestVal(102))
            .await
            .is_ok());

        dbtx.commit_tx().await.expect("DB Error");

        // verify module_dbtx can only read key/value pairs from its own module
        let mut module_dbtx = module_db.begin_transaction().await;
        assert_eq!(module_dbtx.get_value(&TestKey(100)).await.unwrap(), None);

        assert_eq!(module_dbtx.get_value(&TestKey(101)).await.unwrap(), None);

        // verify module_dbtx can read key/value pairs that it wrote
        let mut dbtx = db.begin_transaction().await;
        assert_eq!(
            dbtx.get_value(&TestKey(100)).await.unwrap(),
            Some(TestVal(101))
        );

        assert_eq!(
            dbtx.get_value(&TestKey(101)).await.unwrap(),
            Some(TestVal(102))
        );

        let mut module_dbtx = module_db.begin_transaction().await;

        assert!(module_dbtx
            .insert_entry(&TestKey(100), &TestVal(103))
            .await
            .is_ok());

        assert!(module_dbtx
            .insert_entry(&TestKey(101), &TestVal(104))
            .await
            .is_ok());

        module_dbtx.commit_tx().await.expect("DB Error");

        let expected_keys = 2;
        let mut dbtx = db.begin_transaction().await;
        let returned_keys = dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, kv| async move {
                let (key, value) = kv.unwrap();
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
        assert!(removed.is_ok());
        assert_eq!(removed.unwrap(), Some(TestVal(101)));
        assert_eq!(dbtx.get_value(&TestKey(100)).await.unwrap(), None);

        let mut module_dbtx = module_db.begin_transaction().await;
        assert_eq!(
            module_dbtx.get_value(&TestKey(100)).await.unwrap(),
            Some(TestVal(103))
        );
    }

    pub async fn verify_module_prefix(db: Database) {
        let mut test_dbtx = db.begin_transaction().await;
        {
            let mut test_module_dbtx = test_dbtx.with_module_prefix(TEST_MODULE_PREFIX);

            assert!(test_module_dbtx
                .insert_entry(&TestKey(100), &TestVal(101))
                .await
                .is_ok());

            assert!(test_module_dbtx
                .insert_entry(&TestKey(101), &TestVal(102))
                .await
                .is_ok());
        }

        test_dbtx.commit_tx().await.expect("DB Error");

        let mut alt_dbtx = db.begin_transaction().await;
        {
            let mut alt_module_dbtx = alt_dbtx.with_module_prefix(ALT_MODULE_PREFIX);

            assert!(alt_module_dbtx
                .insert_entry(&TestKey(100), &TestVal(103))
                .await
                .is_ok());

            assert!(alt_module_dbtx
                .insert_entry(&TestKey(101), &TestVal(104))
                .await
                .is_ok());
        }

        alt_dbtx.commit_tx().await.expect("DB Error");

        // verfiy test_module_dbtx can only see key/value pairs from its own module
        let mut test_dbtx = db.begin_transaction().await;
        let mut test_module_dbtx = test_dbtx.with_module_prefix(TEST_MODULE_PREFIX);
        assert_eq!(
            test_module_dbtx.get_value(&TestKey(100)).await.unwrap(),
            Some(TestVal(101))
        );

        assert_eq!(
            test_module_dbtx.get_value(&TestKey(101)).await.unwrap(),
            Some(TestVal(102))
        );

        let expected_keys = 2;
        let returned_keys = test_module_dbtx
            .find_by_prefix(&DbPrefixTestPrefix)
            .await
            .fold(0, |returned_keys, kv| async move {
                let (key, value) = kv.unwrap();
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
        assert!(removed.is_ok());
        assert_eq!(removed.unwrap(), Some(TestVal(101)));
        assert_eq!(
            test_module_dbtx.get_value(&TestKey(100)).await.unwrap(),
            None
        );

        // test_dbtx on its own wont find the key because it does not use a module
        // prefix
        let mut test_dbtx = db.begin_transaction().await;
        assert_eq!(test_dbtx.get_value(&TestKey(101)).await.unwrap(), None);

        test_dbtx.commit_tx().await.expect("DB Error");
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
                .await
                .expect("DB Error");
        }

        dbtx.insert_new_entry(&DatabaseVersionKey, &DatabaseVersion(0))
            .await
            .expect("DB Error");
        dbtx.commit_tx().await.expect("DB Error");

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
        for test_key in test_keys {
            let (key, val) = test_key.unwrap();
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
        dbtx.remove_by_prefix(&DbPrefixTestPrefixV0).await?;
        for pair in example_keys_v0 {
            let (key, val) = pair?;
            let key_v2 = TestKey(key.1);
            dbtx.insert_new_entry(&key_v2, &val).await?;
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
                _value: Vec<u8>,
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
            ) -> crate::db::PrefixStream<'_> {
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
            AutocommitError::CommitFailed { retries, .. } => {
                assert_eq!(retries, 5)
            }
            AutocommitError::ClosureError { .. } => panic!("Closure did not return error"),
        }
    }
}
