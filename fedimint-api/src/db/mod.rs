use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::{error::Error, marker::PhantomData};

use anyhow::Result;
use async_trait::async_trait;
use thiserror::Error;
use tracing::{trace, warn};

use crate::{
    core::ModuleInstanceId,
    encoding::{Decodable, Encodable},
    fmt_utils::AbbreviateHexBytes,
};

pub mod mem_impl;

pub use tests::*;

use crate::module::registry::ModuleDecoderRegistry;

pub const MODULE_GLOBAL_PREFIX: u8 = 0xff;

pub trait DatabaseKeyPrefixConst {
    const DB_PREFIX: u8;
    type Key: DatabaseKey;
    type Value: DatabaseValue;
}

pub trait DatabaseKeyPrefix: Debug {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait DatabaseKey: Sized + DatabaseKeyPrefix {
    fn from_bytes(data: &[u8], modules: &ModuleDecoderRegistry) -> Result<Self, DecodingError>;
}

pub trait SerializableDatabaseValue: Debug {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait DatabaseValue: Sized + SerializableDatabaseValue {
    fn from_bytes(data: &[u8], modules: &ModuleDecoderRegistry) -> Result<Self, DecodingError>;
}

pub type PrefixIter<'a> = Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + Send + 'a>;

#[async_trait]
pub trait IDatabase: Debug + Send + Sync {
    async fn begin_transaction<'a>(&'a self) -> Box<dyn IDatabaseTransaction<'a> + Send + 'a>;
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
    /// Error returned by the closure provided to `autocommit`. If returned no commit was attempted
    /// in that round
    ClosureError {
        /// Retry on which the closure returned an error
        ///
        /// Values other than 0 typically indicate a logic error since the closure given to
        /// `autocommit` should not have side effects and thus keep succeeding if it succeeded once.
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

    /// Runs a closure with a reference to a database transaction and tries to commit the
    /// transaction if the closure returns `Ok` and rolls it back otherwise. If committing fails the
    /// closure is run again for up to `max_retries` times. If `max_retries` is `None` it will run
    /// `usize::MAX` times which is close enough to infinite times.
    ///
    /// The closure `tx_fn` provided should not have side effects outside of the database
    /// transaction provided, or if it does these should be idempotent, since the closure might be
    /// run multiple times.
    ///
    /// # Lifetime Parameters
    ///
    /// The higher rank trait bound (HRTB) `'a` that is applied to the the mutable reference to the
    /// database transaction ensures that the reference lives as least as long as the returned
    /// future of the closure.
    ///
    /// Further, the reference to self (`'s`) must outlive the `DatabaseTransaction<'dt>`. In other
    /// words, the `DatabaseTransaction` must live as least as long as `self` and that is true as
    /// the `DatabaseTransaction` is only dropped at the end of the `loop{}`.
    pub async fn autocommit<'s: 'dt, 'dt, F, T, E>(
        &'s self,
        tx_fn: F,
        max_retries: Option<usize>,
    ) -> Result<T, AutocommitError<E>>
    where
        for<'a> F: Fn(
            &'a mut DatabaseTransaction<'dt>,
        ) -> Pin<Box<dyn Future<Output = Result<T, E>> + 'a>>,
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
                        Err(e) if max_retries.map(|mr| mr >= retries).unwrap_or(false) => {
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

/// Fedimint requires that the database implementation implement Snapshot Isolation.
/// Snapshot Isolation is a database isolation level that guarantees consistent reads
/// from the time that the snapshot was created (at transaction creation time). Transactions
/// with Snapshot Isolation level will only commit if there has been no write to the modified
/// keys since the snapshot (i.e. write-write conflicts are prevented).
///
/// Specifically, Fedimint expects the database implementation to prevent the following
/// anamolies:
///
/// Non-Readable Write: TX1 writes (K1, V1) at time t but cannot read (K1, V1) at time (t + i)
///
/// Dirty Read: TX1 is able to read TX2's uncommitted writes.
///
/// Non-Repeatable Read: TX1 reads (K1, V1) at time t and retrieves (K1, V2) at time (t + i) where
/// V1 != V2.
///
/// Phantom Record: TX1 retrieves X number of records for a prefix at time t and retrieves Y number
/// of records for the same prefix at time (t + i).
///
/// Lost Writes: TX1 writes (K1, V1) at the same time as TX2 writes (K1, V2). V2 overwrites V1 as the
/// value for K1 (write-write conflict).
///
/// | Type     | Non-Readable Write | Dirty Read | Non-Repeatable Read | Phantom Record | Lost Writes |
/// | -------- | ------------------ | ---------- | ------------------- | -------------- | ----------- |
/// | MemoryDB | Prevented          | Prevented  | Prevented           | Prevented      | Possible    |
/// | RocksDB  | Prevented          | Prevented  | Prevented           | Prevented      | Prevented   |
/// | Sqlite   | Prevented          | Prevented  | Prevented           | Prevented      | Prevented   |
#[async_trait]
pub trait IDatabaseTransaction<'a>: 'a + Send {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>>;

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> PrefixIter<'_>;

    /// Default implementation is a combination of [`Self::raw_find_by_prefix`] + loop over [`Self::raw_remove_entry`]
    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        let mut keys = vec![];
        for kv in self.raw_find_by_prefix(key_prefix).await {
            let (k, _) = kv?;
            keys.push(k);
        }

        for keys in &keys {
            self.raw_remove_entry(keys).await?;
        }
        Ok(())
    }

    async fn commit_tx(self: Box<Self>) -> Result<()>;

    async fn rollback_tx_to_savepoint(&mut self);

    /// Create a savepoint during the transaction that can be rolled back to using
    /// rollback_tx_to_savepoint. Rolling back to the savepoint will atomically remove the writes
    /// that were applied since the savepoint was created.
    ///
    /// Warning: Avoid using this in fedimint client code as not all database transaction
    /// implementations will support setting a savepoint during a transaction.
    async fn set_tx_savepoint(&mut self);
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
            warn!("DatabaseTransaction has writes and has not called commit.");
        }
    }
}

/// ModuleDatabaseTransaction is a wrapper around IsolatedDatabaseTransaction that
/// consumes an existing DatabaseTransaction. This allows entire Databases to be
/// isolated and calling begin_transaction will always produce a ModuleDatabaseTransaction,
/// which is isolated from other modules by prepending a prefix to each key.
struct ModuleDatabaseTransaction<'a> {
    dbtx: DatabaseTransaction<'a>,
    prefix: ModuleInstanceId,
}

impl<'a> ModuleDatabaseTransaction<'a> {
    pub fn new(
        dbtx: DatabaseTransaction<'a>,
        prefix: ModuleInstanceId,
    ) -> ModuleDatabaseTransaction<'a> {
        ModuleDatabaseTransaction { dbtx, prefix }
    }
}

#[async_trait]
impl<'a> IDatabaseTransaction<'a> for ModuleDatabaseTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        self.dbtx
            .with_module_prefix(self.prefix)
            .raw_insert_bytes(key, value)
            .await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.dbtx
            .with_module_prefix(self.prefix)
            .raw_get_bytes(key)
            .await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.dbtx
            .with_module_prefix(self.prefix)
            .raw_remove_entry(key)
            .await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> PrefixIter<'_> {
        Box::new(
            self.dbtx
                .with_module_prefix(self.prefix)
                .raw_find_by_prefix(key_prefix)
                .await
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    async fn commit_tx(self: Box<Self>) -> Result<()> {
        panic!("DatabaseTransaction inside modules cannot be committed");
    }

    async fn rollback_tx_to_savepoint(&mut self) {
        self.dbtx
            .with_module_prefix(self.prefix)
            .rollback_tx_to_savepoint()
            .await
    }

    async fn set_tx_savepoint(&mut self) {
        self.dbtx
            .with_module_prefix(self.prefix)
            .set_tx_savepoint()
            .await
    }
}

/// IsolatedDatabaseTransaction is a wrapper around DatabaseTransaction that is responsible for
/// inserting and striping prefixes before reading or writing to the database. It does this by
/// implementing IDatabaseTransaction and manipulating the prefix bytes in the raw insert/get
/// functions. This is done to isolate modules/module instances from each other inside the database,
/// which allows the same module to be instantiated twice or two different modules to use the same
/// key.
struct IsolatedDatabaseTransaction<'isolated, 'parent: 'isolated, T: Send + Encodable> {
    inner_tx: &'isolated mut DatabaseTransaction<'parent>,
    prefix: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<'isolated, 'parent: 'isolated, T: Send + Encodable>
    IsolatedDatabaseTransaction<'isolated, 'parent, T>
{
    pub fn new(
        dbtx: &'isolated mut DatabaseTransaction<'parent>,
        prefix: T,
    ) -> IsolatedDatabaseTransaction<'isolated, 'parent, T> {
        let mut prefix_bytes = vec![MODULE_GLOBAL_PREFIX];
        prefix
            .consensus_encode(&mut prefix_bytes)
            .expect("Error encoding module instance id as prefix");
        IsolatedDatabaseTransaction {
            inner_tx: dbtx,
            prefix: prefix_bytes,
            _marker: PhantomData::<T>,
        }
    }
}

#[async_trait]
impl<'isolated, 'parent, T: Send + Encodable + 'isolated> IDatabaseTransaction<'isolated>
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

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> PrefixIter<'_> {
        let mut prefix_with_module = self.prefix.clone();
        prefix_with_module.extend_from_slice(key_prefix);
        let raw_prefix = self
            .inner_tx
            .raw_find_by_prefix(prefix_with_module.as_slice())
            .await;
        Box::new(raw_prefix.map(|pair| match pair {
            Ok(kv) => {
                let key = kv.0;
                let stripped_key = &key[(self.prefix.len())..];
                Ok((stripped_key.to_vec(), kv.1))
            }
            _ => pair,
        }))
    }

    async fn commit_tx(self: Box<Self>) -> Result<()> {
        panic!("DatabaseTransaction inside modules cannot be committed");
    }

    async fn rollback_tx_to_savepoint(&mut self) {
        self.inner_tx.rollback_tx_to_savepoint().await
    }

    async fn set_tx_savepoint(&mut self) {
        self.inner_tx.set_tx_savepoint().await
    }
}

#[doc = " A handle to a type-erased database implementation"]
pub struct DatabaseTransaction<'a> {
    tx: Box<dyn IDatabaseTransaction<'a> + Send + 'a>,
    decoders: ModuleDecoderRegistry,
    commit_tracker: CommitTracker,
}

impl<'a> std::ops::Deref for DatabaseTransaction<'a> {
    type Target = dyn IDatabaseTransaction<'a> + Send + 'a;

    fn deref(&self) -> &<Self as std::ops::Deref>::Target {
        &*self.tx
    }
}

impl<'a> std::ops::DerefMut for DatabaseTransaction<'a> {
    fn deref_mut(&mut self) -> &mut <Self as std::ops::Deref>::Target {
        &mut *self.tx
    }
}

impl<'parent> DatabaseTransaction<'parent> {
    pub fn new(
        dbtx: Box<dyn IDatabaseTransaction<'parent> + Send + 'parent>,
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
    ) -> DatabaseTransaction<'isolated>
    where
        'parent: 'isolated,
    {
        let decoders = self.decoders.clone();
        let isolated = Box::new(IsolatedDatabaseTransaction::new(self, module_instance_id));
        DatabaseTransaction {
            tx: isolated,
            decoders,
            // DatabaseTransaction passed to modules cannot be committed, so the commit tracker is set to committed to surpress the warning
            commit_tracker: CommitTracker {
                is_committed: true,
                has_writes: true,
            },
        }
    }

    pub fn new_module_tx(
        self,
        module_instance_id: ModuleInstanceId,
    ) -> DatabaseTransaction<'parent> {
        let decoders = self.decoders.clone();
        let commit_tracker = self.commit_tracker.clone();
        let wrapped = ModuleDatabaseTransaction::new(self, module_instance_id);
        DatabaseTransaction {
            tx: Box::new(wrapped),
            decoders,
            commit_tracker,
        }
    }

    pub async fn commit_tx(mut self) -> Result<()> {
        self.commit_tracker.is_committed = true;
        return self.tx.commit_tx().await;
    }

    pub async fn get_value<K>(&mut self, key: &K) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.tx.raw_get_bytes(&key_bytes).await? {
            Some(value) => value,
            None => return Ok(None),
        };

        trace!(
            "get_value: Decoding {} from bytes {}",
            std::any::type_name::<K::Value>(),
            AbbreviateHexBytes(&value_bytes)
        );
        Ok(Some(K::Value::from_bytes(&value_bytes, &self.decoders)?))
    }

    pub async fn find_by_prefix<KP>(
        &mut self,
        key_prefix: &KP,
    ) -> impl Iterator<Item = Result<(KP::Key, KP::Value)>> + '_
    where
        KP: DatabaseKeyPrefix + DatabaseKeyPrefixConst,
    {
        let decoders = self.decoders.clone();
        let prefix_bytes = key_prefix.to_bytes();
        self.tx
            .raw_find_by_prefix(&prefix_bytes)
            .await
            .map(move |res| {
                res.and_then(|(key_bytes, value_bytes)| {
                    let key = KP::Key::from_bytes(&key_bytes, &decoders)?;
                    trace!(
                        "find by prefix: Decoding {} from bytes {}",
                        std::any::type_name::<KP::Value>(),
                        AbbreviateHexBytes(&value_bytes)
                    );
                    let value = KP::Value::from_bytes(&value_bytes, &decoders)?;
                    Ok((key, value))
                })
            })
    }

    pub async fn insert_entry<K>(&mut self, key: &K, value: &K::Value) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        self.commit_tracker.has_writes = true;
        match self
            .raw_insert_bytes(&key.to_bytes(), value.to_bytes())
            .await?
        {
            Some(old_val_bytes) => {
                trace!(
                    "insert_entry: Decoding {} from bytes {}",
                    std::any::type_name::<K::Value>(),
                    AbbreviateHexBytes(&old_val_bytes)
                );
                Ok(Some(K::Value::from_bytes(&old_val_bytes, &self.decoders)?))
            }
            None => Ok(None),
        }
    }

    pub async fn insert_new_entry<K>(
        &mut self,
        key: &K,
        value: &K::Value,
    ) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        self.commit_tracker.has_writes = true;
        match self
            .raw_insert_bytes(&key.to_bytes(), value.to_bytes())
            .await?
        {
            Some(_) => {
                warn!(
                    "Database overwriting element when expecting insertion of new entry. Key: {:?}",
                    key
                );
                Ok(None)
            }
            None => Ok(None),
        }
    }

    pub async fn remove_entry<K>(&mut self, key: &K) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        self.commit_tracker.has_writes = true;
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_remove_entry(&key_bytes).await? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(K::Value::from_bytes(&value_bytes, &self.decoders)?))
    }

    pub async fn remove_by_prefix<KP>(&mut self, key_prefix: &KP) -> Result<()>
    where
        KP: DatabaseKeyPrefix + DatabaseKeyPrefixConst,
    {
        self.commit_tracker.has_writes = true;
        self.raw_remove_by_prefix(&key_prefix.to_bytes()).await
    }
}

impl<T> DatabaseKeyPrefix for T
where
    T: DatabaseKeyPrefixConst + crate::encoding::Encodable + Debug,
{
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec![Self::DB_PREFIX];
        self.consensus_encode(&mut data)
            .expect("Writing to vec is infallible");
        data
    }
}

impl<T> DatabaseKey for T
where
    // Note: key can only be `T` that can be decoded without modules (even if module type is `()`)
    T: DatabaseKeyPrefix + DatabaseKeyPrefixConst + crate::encoding::Decodable + Sized,
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

impl<T> SerializableDatabaseValue for T
where
    T: Encodable + Debug,
{
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes)
            .expect("writing to vec can't fail");
        bytes
    }
}

impl<T> DatabaseValue for T
where
    T: SerializableDatabaseValue + Decodable,
{
    fn from_bytes(data: &[u8], modules: &ModuleDecoderRegistry) -> Result<Self, DecodingError> {
        T::consensus_decode(&mut std::io::Cursor::new(data), modules)
            .map_err(|e| DecodingError::Other(e.0))
    }
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

mod tests {
    use super::Database;
    use crate::db::DatabaseKeyPrefixConst;
    use crate::encoding::{Decodable, Encodable};

    #[repr(u8)]
    #[derive(Clone)]
    pub enum TestDbKeyPrefix {
        Test = 0x42,
        AltTest = 0x43,
        PercentTestKey = 0x25,
    }

    #[derive(Debug, Encodable, Decodable)]
    struct TestKey(u64);

    impl DatabaseKeyPrefixConst for TestKey {
        const DB_PREFIX: u8 = TestDbKeyPrefix::Test as u8;
        type Key = Self;
        type Value = TestVal;
    }

    #[derive(Debug, Encodable, Decodable)]
    struct DbPrefixTestPrefix;

    impl DatabaseKeyPrefixConst for DbPrefixTestPrefix {
        const DB_PREFIX: u8 = TestDbKeyPrefix::Test as u8;
        type Key = TestKey;
        type Value = TestVal;
    }

    #[derive(Debug, Encodable, Decodable)]
    struct AltTestKey(u64);

    impl DatabaseKeyPrefixConst for AltTestKey {
        const DB_PREFIX: u8 = TestDbKeyPrefix::AltTest as u8;
        type Key = Self;
        type Value = TestVal;
    }

    #[derive(Debug, Encodable, Decodable)]
    struct AltDbPrefixTestPrefix;

    impl DatabaseKeyPrefixConst for AltDbPrefixTestPrefix {
        const DB_PREFIX: u8 = TestDbKeyPrefix::AltTest as u8;
        type Key = AltTestKey;
        type Value = TestVal;
    }

    #[derive(Debug, Encodable, Decodable)]
    struct PercentTestKey(u64);

    impl DatabaseKeyPrefixConst for PercentTestKey {
        const DB_PREFIX: u8 = TestDbKeyPrefix::PercentTestKey as u8;
        type Key = Self;
        type Value = TestVal;
    }

    #[derive(Debug, Encodable, Decodable)]
    struct PercentPrefixTestPrefix;

    impl DatabaseKeyPrefixConst for PercentPrefixTestPrefix {
        const DB_PREFIX: u8 = TestDbKeyPrefix::PercentTestKey as u8;
        type Key = PercentTestKey;
        type Value = TestVal;
    }

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
        let mut returned_keys = 0;
        let expected_keys = 2;
        for res in dbtx.find_by_prefix(&DbPrefixTestPrefix).await {
            match res.as_ref().unwrap().0 {
                TestKey(55) => {
                    assert!(res.unwrap().1.eq(&TestVal(9999)));
                    returned_keys += 1;
                }
                TestKey(54) => {
                    assert!(res.unwrap().1.eq(&TestVal(8888)));
                    returned_keys += 1;
                }
                _ => {
                    returned_keys += 1;
                }
            }
        }

        assert_eq!(returned_keys, expected_keys);

        let mut returned_keys = 0;
        let expected_keys = 2;
        for res in dbtx.find_by_prefix(&AltDbPrefixTestPrefix).await {
            match res.as_ref().unwrap().0 {
                AltTestKey(55) => {
                    assert!(res.unwrap().1.eq(&TestVal(7777)));
                    returned_keys += 1;
                }
                AltTestKey(54) => {
                    assert!(res.unwrap().1.eq(&TestVal(6666)));
                    returned_keys += 1;
                }
                _ => {
                    returned_keys += 1;
                }
            }
        }

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

        dbtx_rollback.set_tx_savepoint().await;

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

        dbtx_rollback.rollback_tx_to_savepoint().await;

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

        let mut returned_keys = 0;
        let expected_keys = 0;
        for res in dbtx.find_by_prefix(&DbPrefixTestPrefix).await {
            match res.as_ref().unwrap().0 {
                TestKey(100) => {
                    assert!(res.unwrap().1.eq(&TestVal(101)));
                    returned_keys += 1;
                }
                _ => {
                    returned_keys += 1;
                }
            }
        }

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
        let mut returned_keys = 0;
        let expected_keys = 2;
        for res in dbtx.find_by_prefix(&DbPrefixTestPrefix).await {
            match res.as_ref().unwrap().0 {
                TestKey(100) => {
                    assert!(res.unwrap().1.eq(&TestVal(101)));
                    returned_keys += 1;
                }
                TestKey(101) => {
                    assert!(res.unwrap().1.eq(&TestVal(102)));
                    returned_keys += 1;
                }
                _ => {
                    returned_keys += 1;
                }
            }
        }

        assert_eq!(returned_keys, expected_keys);

        let mut dbtx2 = db.begin_transaction().await;

        assert!(dbtx2
            .insert_entry(&TestKey(102), &TestVal(103))
            .await
            .is_ok());

        dbtx2.commit_tx().await.expect("DB Error");

        let mut returned_keys = 0;
        for res in dbtx.find_by_prefix(&DbPrefixTestPrefix).await {
            match res.as_ref().unwrap().0 {
                TestKey(100) => {
                    assert!(res.unwrap().1.eq(&TestVal(101)));
                    returned_keys += 1;
                }
                TestKey(101) => {
                    assert!(res.unwrap().1.eq(&TestVal(102)));
                    returned_keys += 1;
                }
                _ => {
                    returned_keys += 1;
                }
            }
        }

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

        // Depending on if the database implementation supports optimistic or pessimistic transactions, this test should generate
        // an error here (pessimistic) or at commit time (optimistic)
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

        // If the wildcard character ('%') is not handled properly, this will make find_by_prefix return 5 results instead of 4
        assert!(dbtx
            .insert_entry(&TestKey(101), &TestVal(100))
            .await
            .is_ok());

        let mut returned_keys = 0;
        let expected_keys = 4;
        for res in dbtx.find_by_prefix(&PercentPrefixTestPrefix).await {
            match res.as_ref().unwrap().0 {
                PercentTestKey(101) => {
                    assert!(res.unwrap().1.eq(&TestVal(100)));
                    returned_keys += 1;
                }
                _ => {
                    returned_keys += 1;
                }
            }
        }

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
        let mut returned_keys = 0;
        let expected_keys = 0;
        for res in dbtx.find_by_prefix(&DbPrefixTestPrefix).await {
            match res.as_ref().unwrap().0 {
                TestKey(100) => {
                    assert!(res.unwrap().1.eq(&TestVal(101)));
                    returned_keys += 1;
                }
                TestKey(101) => {
                    assert!(res.unwrap().1.eq(&TestVal(102)));
                    returned_keys += 1;
                }
                _ => {
                    returned_keys += 1;
                }
            }
        }

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

        let mut returned_keys = 0;
        let expected_keys = 2;
        let mut dbtx = db.begin_transaction().await;
        for res in dbtx.find_by_prefix(&DbPrefixTestPrefix).await {
            match res.as_ref().unwrap().0 {
                TestKey(100) => {
                    assert!(res.unwrap().1.eq(&TestVal(101)));
                    returned_keys += 1;
                }
                TestKey(101) => {
                    assert!(res.unwrap().1.eq(&TestVal(102)));
                    returned_keys += 1;
                }
                _ => {
                    returned_keys += 1;
                }
            }
        }

        assert_eq!(returned_keys, expected_keys);

        let removed = dbtx.remove_entry(&TestKey(100)).await;
        assert!(removed.is_ok());
        assert_eq!(removed.unwrap(), Some(TestVal(101)));
        assert_eq!(dbtx.get_value(&TestKey(100)).await.unwrap(), None);

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

        let mut returned_keys = 0;
        let expected_keys = 2;
        for res in test_module_dbtx.find_by_prefix(&DbPrefixTestPrefix).await {
            match res.as_ref().unwrap().0 {
                TestKey(100) => {
                    assert!(res.unwrap().1.eq(&TestVal(101)));
                    returned_keys += 1;
                }
                TestKey(101) => {
                    assert!(res.unwrap().1.eq(&TestVal(102)));
                    returned_keys += 1;
                }
                _ => {
                    returned_keys += 1;
                }
            }
        }

        assert_eq!(returned_keys, expected_keys);

        let removed = test_module_dbtx.remove_entry(&TestKey(100)).await;
        assert!(removed.is_ok());
        assert_eq!(removed.unwrap(), Some(TestVal(101)));
        assert_eq!(
            test_module_dbtx.get_value(&TestKey(100)).await.unwrap(),
            None
        );

        // test_dbtx on its own wont find the key because it does not use a module prefix
        let mut test_dbtx = db.begin_transaction().await;
        assert_eq!(test_dbtx.get_value(&TestKey(101)).await.unwrap(), None);

        test_dbtx.commit_tx().await.expect("DB Error");
    }
}
