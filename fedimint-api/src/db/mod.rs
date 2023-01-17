use std::error::Error;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use thiserror::Error;
use tracing::{trace, warn};

use crate::encoding::{Decodable, Encodable};
use crate::fmt_utils::AbbreviateHexBytes;

pub mod mem_impl;

pub use tests::*;

use crate::module::registry::ModuleDecoderRegistry;

#[derive(Debug, Default)]
pub struct DatabaseInsertOperation {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct DatabaseDeleteOperation {
    pub key: Vec<u8>,
}

#[derive(Debug)]
pub enum DatabaseOperation {
    Insert(DatabaseInsertOperation),
    Delete(DatabaseDeleteOperation),
}

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
pub struct Database(Arc<DatabaseInner<dyn IDatabase>>);

// NOTE: `Db` is used instead of just `dyn IDatabase`
// because it will impossible to construct otherwise
#[derive(Debug)]
struct DatabaseInner<Db: IDatabase + ?Sized> {
    module_decoders: ModuleDecoderRegistry,
    db: Db,
}

impl Database {
    pub fn new(db: impl IDatabase + 'static, module_decoders: ModuleDecoderRegistry) -> Self {
        let inner = DatabaseInner {
            db,
            module_decoders,
        };

        Self(Arc::new(inner))
    }

    pub async fn begin_transaction(&self) -> DatabaseTransaction {
        DatabaseTransaction::new(self.0.db.begin_transaction().await, &self.0.module_decoders)
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
/// | SledDB   | Prevented          | Prevented  | Possible            | Possible       | Possible    |
/// | RocksDB  | Prevented          | Prevented  | Prevented           | Prevented      | Prevented   |
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

#[doc = " A handle to a type-erased database implementation"]
pub struct DatabaseTransaction<'a> {
    tx: Box<dyn IDatabaseTransaction<'a> + Send + 'a>,
    decoders: &'a ModuleDecoderRegistry,
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

impl<'a> DatabaseTransaction<'a> {
    pub fn new(
        dbtx: Box<dyn IDatabaseTransaction<'a> + Send + 'a>,
        decoders: &'a ModuleDecoderRegistry,
    ) -> DatabaseTransaction<'a> {
        DatabaseTransaction {
            tx: dbtx,
            decoders,
            commit_tracker: CommitTracker {
                is_committed: false,
                has_writes: false,
            },
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
        Ok(Some(K::Value::from_bytes(&value_bytes, self.decoders)?))
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
                Ok(Some(K::Value::from_bytes(&old_val_bytes, self.decoders)?))
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

        Ok(Some(K::Value::from_bytes(&value_bytes, self.decoders)?))
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
}
