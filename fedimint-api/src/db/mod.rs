use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::Result;
use batch::DbBatch;
use thiserror::Error;
use tracing::{trace, warn};

use crate::dyn_newtype_define;
use crate::encoding::{Decodable, Encodable, ModuleRegistry};
use crate::module::{ModuleDecoder, ServerModule};

pub mod batch;
pub mod mem_impl;

pub use tests::test_db_impl;
pub use tests::test_dbtx_impl;

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
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError>;
}

pub trait SerializableDatabaseValue: Debug {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait DatabaseValue: Sized + SerializableDatabaseValue {
    fn from_bytes<M>(data: &[u8], modules: &ModuleRegistry<M>) -> Result<Self, DecodingError>
    where
        M: ModuleDecoder;
}

pub type PrefixIter<'a> = Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + Send + 'a>;

pub trait IDatabase: Send + Sync {
    fn raw_insert_entry(&self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>>;

    fn raw_get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    fn raw_remove_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    fn raw_find_by_prefix(&self, key_prefix: &[u8]) -> PrefixIter<'_>;

    fn raw_apply_batch(&self, batch: DbBatch) -> Result<()>;

    fn begin_transaction(&self) -> DatabaseTransaction;
}

dyn_newtype_define! {
    /// A handle to a type-erased database implementation
    #[derive(Clone)]
    pub Database(Arc<IDatabase>)
}

impl Database {
    pub fn insert_entry<K>(&self, key: &K, value: &K::Value) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        match self.raw_insert_entry(&key.to_bytes(), value.to_bytes())? {
            Some(old_val_bytes) => {
                trace!(
                    "insert_entry: Decoding {} from bytes {:?}",
                    std::any::type_name::<K::Value>(),
                    old_val_bytes
                );
                Ok(Some(K::Value::from_bytes(
                    &old_val_bytes,
                    &BTreeMap::<_, ServerModule>::new(),
                )?))
            }
            None => Ok(None),
        }
    }

    pub fn get_value<K>(&self, key: &K) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_get_value(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        trace!(
            "get_value: Decoding {} from bytes {:?}",
            std::any::type_name::<K::Value>(),
            value_bytes
        );
        Ok(Some(K::Value::from_bytes(
            &value_bytes,
            &BTreeMap::<_, ServerModule>::new(),
        )?))
    }

    pub fn remove_entry<K>(&self, key: &K) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_remove_entry(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        trace!(
            "remove_entry: Decoding {} from bytes {:?}",
            std::any::type_name::<K::Value>(),
            value_bytes
        );
        Ok(Some(K::Value::from_bytes(
            &value_bytes,
            &BTreeMap::<_, ServerModule>::new(),
        )?))
    }

    pub fn find_by_prefix<KP>(
        &self,
        key_prefix: &KP,
    ) -> impl Iterator<Item = Result<(KP::Key, KP::Value)>> + '_
    where
        KP: DatabaseKeyPrefix + DatabaseKeyPrefixConst,
    {
        let prefix_bytes = key_prefix.to_bytes();
        self.raw_find_by_prefix(&prefix_bytes).map(|res| {
            res.and_then(|(key_bytes, value_bytes)| {
                let key = KP::Key::from_bytes(&key_bytes)?;
                trace!(
                    "find by prefix: Decoding {} from bytes {:?}",
                    std::any::type_name::<KP::Value>(),
                    value_bytes
                );
                let value =
                    KP::Value::from_bytes(&value_bytes, &BTreeMap::<_, ServerModule>::new())?;
                Ok((key, value))
            })
        })
    }

    pub fn apply_batch(&self, batch: DbBatch) -> Result<()> {
        self.raw_apply_batch(batch)
    }
}

pub trait IDatabaseTransaction<'a>: 'a {
    fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>>;

    fn raw_get_bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    fn raw_remove_entry(&mut self, key: &[u8]) -> Result<()>;

    fn raw_find_by_prefix(&self, key_prefix: &[u8]) -> PrefixIter<'_>;

    fn commit_tx(self: Box<Self>) -> Result<()>;

    fn rollback_tx_to_savepoint(&mut self);

    // Ideally, avoid using this in fedimint client code as not all database transaction
    // implementations will support setting a savepoint during a transaction.
    fn set_tx_savepoint(&mut self);
}

dyn_newtype_define! {
    /// A handle to a type-erased database implementation
    pub DatabaseTransaction<'a>(Box<IDatabaseTransaction>)
}

impl<'a> DatabaseTransaction<'a> {
    pub fn commit_tx(self) -> Result<()> {
        self.0.commit_tx()
    }
}

impl<'a> DatabaseTransaction<'a> {
    pub fn insert_entry<K>(&mut self, key: &K, value: &K::Value) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        match self.0.raw_insert_bytes(&key.to_bytes(), value.to_bytes())? {
            Some(old_val_bytes) => {
                trace!(
                    "insert_bytes: Decoding {} from bytes {:?}",
                    std::any::type_name::<K::Value>(),
                    old_val_bytes
                );
                Ok(Some(K::Value::from_bytes(
                    &old_val_bytes,
                    &BTreeMap::<_, ServerModule>::new(),
                )?))
            }
            None => Ok(None),
        }
    }

    pub fn insert_new_entry<K>(&mut self, key: &K, value: &K::Value) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        match self.0.raw_insert_bytes(&key.to_bytes(), value.to_bytes())? {
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

    pub fn get_value<K>(&self, key: &K) -> Result<Option<K::Value>>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_get_bytes(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        trace!(
            "get_value: Decoding {} from bytes {:?}",
            std::any::type_name::<K::Value>(),
            value_bytes
        );
        Ok(Some(K::Value::from_bytes(
            &value_bytes,
            &BTreeMap::<_, ServerModule>::new(),
        )?))
    }

    pub fn remove_entry<K>(&mut self, key: &K) -> Result<()>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        match self.raw_get_bytes(&key.to_bytes())? {
            None => {
                warn!(
                    "Database remove absent element when expecting element to exist. Key: {:?}",
                    key
                );
            }
            Some(_) => {
                self.raw_remove_entry(&key.to_bytes())?;
            }
        }
        Ok(())
    }

    pub fn maybe_remove_entry<K>(&mut self, key: &K) -> Result<()>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        self.raw_remove_entry(&key.to_bytes())?;
        Ok(())
    }

    pub fn find_by_prefix<KP>(
        &self,
        key_prefix: &KP,
    ) -> impl Iterator<Item = Result<(KP::Key, KP::Value)>> + '_
    where
        KP: DatabaseKeyPrefix + DatabaseKeyPrefixConst,
    {
        let prefix_bytes = key_prefix.to_bytes();
        self.raw_find_by_prefix(&prefix_bytes).map(|res| {
            res.and_then(|(key_bytes, value_bytes)| {
                let key = KP::Key::from_bytes(&key_bytes)?;
                trace!(
                    "find by prefix: Decoding {} from bytes {:?}",
                    std::any::type_name::<KP::Value>(),
                    value_bytes
                );
                let value =
                    KP::Value::from_bytes(&value_bytes, &BTreeMap::<_, ServerModule>::new())?;
                Ok((key, value))
            })
        })
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
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.is_empty() {
            // TODO: build better coding errors, pretty useless right now
            return Err(DecodingError::wrong_length(1, 0));
        }

        if data[0] != Self::DB_PREFIX {
            return Err(DecodingError::wrong_prefix(Self::DB_PREFIX, data[0]));
        }

        <Self as crate::encoding::Decodable>::consensus_decode(
            &mut std::io::Cursor::new(&data[1..]),
            &BTreeMap::<_, ()>::new(),
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
    fn from_bytes<M>(data: &[u8], modules: &ModuleRegistry<M>) -> Result<Self, DecodingError>
    where
        M: ModuleDecoder,
    {
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

    const DB_PREFIX_TEST: u8 = 0x42;
    const ALT_DB_PREFIX_TEST: u8 = 0x43;

    #[derive(Debug, Encodable, Decodable)]
    struct TestKey(u64);

    impl DatabaseKeyPrefixConst for TestKey {
        const DB_PREFIX: u8 = DB_PREFIX_TEST;
        type Key = Self;
        type Value = TestVal;
    }

    #[derive(Debug, Encodable, Decodable)]
    struct DbPrefixTestPrefix;

    impl DatabaseKeyPrefixConst for DbPrefixTestPrefix {
        const DB_PREFIX: u8 = DB_PREFIX_TEST;
        type Key = TestKey;
        type Value = TestVal;
    }

    #[derive(Debug, Encodable, Decodable)]
    struct AltTestKey(u64);

    impl DatabaseKeyPrefixConst for AltTestKey {
        const DB_PREFIX: u8 = ALT_DB_PREFIX_TEST;
        type Key = Self;
        type Value = TestVal;
    }

    #[derive(Debug, Encodable, Decodable)]
    struct AltDbPrefixTestPrefix;

    impl DatabaseKeyPrefixConst for AltDbPrefixTestPrefix {
        const DB_PREFIX: u8 = ALT_DB_PREFIX_TEST;
        type Key = AltTestKey;
        type Value = TestVal;
    }

    #[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
    struct TestVal(u64);

    pub fn test_db_impl(db: Database) {
        assert!(db
            .insert_entry(&TestKey(42), &TestVal(1337))
            .unwrap()
            .is_none());
        assert!(db
            .insert_entry(&TestKey(123), &TestVal(456))
            .unwrap()
            .is_none());

        assert_eq!(db.get_value(&TestKey(42)).unwrap(), Some(TestVal(1337)));
        assert_eq!(db.get_value(&TestKey(123)).unwrap(), Some(TestVal(456)));
        assert_eq!(db.get_value(&TestKey(43)).unwrap(), None);

        db.insert_entry(&TestKey(42), &TestVal(3301)).unwrap();
        assert_eq!(db.get_value(&TestKey(42)).unwrap(), Some(TestVal(3301)));

        let removed = db.remove_entry(&TestKey(42)).unwrap();
        assert_eq!(removed, Some(TestVal(3301)));
        assert_eq!(db.get_value(&TestKey(42)).unwrap(), None);

        assert!(db
            .insert_entry(&TestKey(42), &TestVal(0))
            .unwrap()
            .is_none());
        assert!(db.get_value(&TestKey(42)).is_ok());

        assert!(db.insert_entry(&TestKey(55), &TestVal(9999)).is_ok());
        assert!(db.insert_entry(&TestKey(54), &TestVal(8888)).is_ok());

        assert!(db.insert_entry(&AltTestKey(55), &TestVal(7777)).is_ok());
        assert!(db.insert_entry(&AltTestKey(54), &TestVal(6666)).is_ok());

        for res in db.find_by_prefix(&DbPrefixTestPrefix) {
            match res.as_ref().unwrap().0 {
                TestKey(55) => assert!(res.unwrap().1.eq(&TestVal(9999))),
                TestKey(54) => assert!(res.unwrap().1.eq(&TestVal(8888))),
                _ => {}
            }
        }

        for res in db.find_by_prefix(&AltDbPrefixTestPrefix) {
            match res.as_ref().unwrap().0 {
                AltTestKey(55) => assert!(res.unwrap().1.eq(&TestVal(7777))),
                AltTestKey(54) => assert!(res.unwrap().1.eq(&TestVal(6666))),
                _ => {}
            }
        }
    }

    pub fn test_dbtx_impl(db: Database) {
        let mut dbtx = db.begin_transaction();

        assert!(dbtx
            .insert_entry(&TestKey(42), &TestVal(1337))
            .unwrap()
            .is_none());
        assert!(dbtx
            .insert_entry(&TestKey(123), &TestVal(456))
            .unwrap()
            .is_none());

        // Verify that we can read our own writes before committing
        assert_eq!(dbtx.get_value(&TestKey(42)).unwrap(), Some(TestVal(1337)));
        assert_eq!(dbtx.get_value(&TestKey(123)).unwrap(), Some(TestVal(456)));
        assert_eq!(dbtx.get_value(&TestKey(43)).unwrap(), None);

        // Verify that new transactions cannot read writes of other transactions
        let dbtx2 = db.begin_transaction();
        assert_eq!(dbtx2.get_value(&TestKey(42)).unwrap(), None);
        assert_eq!(dbtx2.get_value(&TestKey(123)).unwrap(), None);
        assert_eq!(dbtx2.get_value(&TestKey(43)).unwrap(), None);

        let removed = dbtx.remove_entry(&TestKey(42));
        assert!(removed.is_ok());
        assert_eq!(dbtx.get_value(&TestKey(42)).unwrap(), None);

        assert!(dbtx
            .insert_entry(&TestKey(42), &TestVal(0))
            .unwrap()
            .is_none());
        assert!(dbtx.get_value(&TestKey(42)).is_ok());

        assert!(dbtx.insert_entry(&TestKey(55), &TestVal(9999)).is_ok());
        assert!(dbtx.insert_entry(&TestKey(54), &TestVal(8888)).is_ok());

        assert!(dbtx.insert_entry(&AltTestKey(55), &TestVal(7777)).is_ok());
        assert!(dbtx.insert_entry(&AltTestKey(54), &TestVal(6666)).is_ok());

        let mut returned_keys = 0;
        let expected_keys = 2;
        for res in dbtx.find_by_prefix(&DbPrefixTestPrefix) {
            match res.as_ref().unwrap().0 {
                TestKey(55) => {
                    assert!(res.unwrap().1.eq(&TestVal(9999)));
                    returned_keys += 1;
                }
                TestKey(54) => {
                    assert!(res.unwrap().1.eq(&TestVal(8888)));
                    returned_keys += 1;
                }
                _ => {}
            }
        }

        assert_eq!(returned_keys, expected_keys);

        let mut returned_keys = 0;
        let expected_keys = 2;
        for res in dbtx.find_by_prefix(&AltDbPrefixTestPrefix) {
            match res.as_ref().unwrap().0 {
                AltTestKey(55) => {
                    assert!(res.unwrap().1.eq(&TestVal(7777)));
                    returned_keys += 1;
                }
                AltTestKey(54) => {
                    assert!(res.unwrap().1.eq(&TestVal(6666)));
                    returned_keys += 1;
                }
                _ => {}
            }
        }

        assert_eq!(returned_keys, expected_keys);

        // Verify that other transactions can read committed transactions
        dbtx.commit_tx().expect("DB Error");
        let dbtx3 = db.begin_transaction();
        assert_eq!(dbtx3.get_value(&TestKey(42)).unwrap(), Some(TestVal(0)));
        assert_eq!(dbtx3.get_value(&TestKey(55)).unwrap(), Some(TestVal(9999)));
        assert_eq!(dbtx3.get_value(&TestKey(54)).unwrap(), Some(TestVal(8888)));

        // Verify that setting a savepoint and rolling back a transaction erases a write
        let mut dbtx_rollback = db.begin_transaction();

        assert!(dbtx_rollback
            .insert_entry(&TestKey(20), &TestVal(2000))
            .is_ok());

        dbtx_rollback.set_tx_savepoint();

        assert!(dbtx_rollback
            .insert_entry(&TestKey(21), &TestVal(2001))
            .is_ok());

        assert_eq!(
            dbtx_rollback.get_value(&TestKey(20)).unwrap(),
            Some(TestVal(2000))
        );
        assert_eq!(
            dbtx_rollback.get_value(&TestKey(21)).unwrap(),
            Some(TestVal(2001))
        );

        dbtx_rollback.rollback_tx_to_savepoint();

        assert_eq!(
            dbtx_rollback.get_value(&TestKey(20)).unwrap(),
            Some(TestVal(2000))
        );

        assert_eq!(dbtx_rollback.get_value(&TestKey(21)).unwrap(), None);
    }
}
