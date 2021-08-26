use crate::batch::DbBatch;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::borrow::Cow;
use std::error::Error;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;
use thiserror::Error;

pub mod batch;
pub mod mem_impl;
pub mod sled_impl;

// FIXME: rework API using encoding traits
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
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError>;
}

pub trait RawDatabase: Send + Sync {
    fn raw_insert_entry(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, DatabaseError>;

    fn raw_get_value(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, DatabaseError>;

    fn raw_remove_entry(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, DatabaseError>;

    fn raw_find_by_prefix(
        &self,
        key_prefix: Vec<u8>,
    ) -> Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>), DatabaseError>>>;

    fn raw_apply_batch(&self, batch: DbBatch) -> Result<(), DatabaseError>;
}

pub trait Database {
    fn insert_entry<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue;

    fn get_value<K, V>(&self, key: &K) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue;

    fn remove_entry<K, V>(&self, key: &K) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue;

    fn find_by_prefix<KP, K, V>(&self, key_prefix: &KP) -> DbIter<K, V>
    where
        KP: DatabaseKeyPrefix,
        K: DatabaseKey,
        V: DatabaseValue;

    /// Apply a batch atomically
    fn apply_batch(&self, batch: DbBatch) -> Result<(), DatabaseError>;
}

pub struct DbIter<K, V>
where
    K: DatabaseKey,
    V: DatabaseValue,
{
    iter: Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>), DatabaseError>>>,
    _pd: PhantomData<(K, V)>,
}

#[derive(Debug)]
pub struct BincodeSerialized<'a, T: Clone>(Cow<'a, T>);

impl<'a, D> Database for D
where
    D: Deref<Target = dyn RawDatabase + 'a> + ?Sized,
{
    fn insert_entry<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        match self.raw_insert_entry(key.to_bytes(), value.to_bytes())? {
            Some(old_val_bytes) => Ok(Some(V::from_bytes(&old_val_bytes)?)),
            None => Ok(None),
        }
    }

    fn get_value<K, V>(&self, key: &K) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_get_value(key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(V::from_bytes(&value_bytes)?))
    }

    fn remove_entry<K, V>(&self, key: &K) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_remove_entry(key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(V::from_bytes(&value_bytes)?))
    }

    fn find_by_prefix<KP, K, V>(&self, key_prefix: &KP) -> DbIter<K, V>
    where
        KP: DatabaseKeyPrefix,
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let prefix_bytes = key_prefix.to_bytes();
        DbIter {
            iter: self.raw_find_by_prefix(prefix_bytes),
            _pd: Default::default(),
        }
    }

    fn apply_batch(&self, batch: DbBatch) -> Result<(), DatabaseError> {
        self.raw_apply_batch(batch)
    }
}

impl<K, V> Iterator for DbIter<K, V>
where
    K: DatabaseKey,
    V: DatabaseValue,
{
    type Item = Result<(K, V), DatabaseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next()? {
            Ok((key_bytes, value_bytes)) => {
                let key = match K::from_bytes(key_bytes.as_ref()) {
                    Ok(key) => key,
                    Err(e) => return Some(Err(e.into())),
                };
                let value = match V::from_bytes(value_bytes.as_ref()) {
                    Ok(value) => value,
                    Err(e) => return Some(Err(e.into())),
                };
                Some(Ok((key, value)))
            }
            Err(e) => Some(Err(e.into())),
        }
    }
}

impl SerializableDatabaseValue for () {
    fn to_bytes(&self) -> Vec<u8> {
        vec![].into()
    }
}

impl DatabaseValue for () {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(DecodingError::wrong_length(0, data.len()))
        }
    }
}

/// Checks a key of fixed length for the right `prefix` and data length. On success it returns a slice
/// of length `len` with the prefix cut off.
pub fn check_format(data: &[u8], prefix: u8, len: usize) -> Result<&[u8], DecodingError> {
    if len + 1 != data.len() {
        Err(DecodingError::wrong_length(len, data.len()))
    } else if data[0] != prefix {
        Err(DecodingError::wrong_prefix(prefix, data[0]))
    } else {
        Ok(&data[1..])
    }
}

#[derive(Debug, Error)]
pub enum DecodingError {
    #[error("Key had a wrong prefix, expected {expected} but got {found}")]
    WrongPrefix { expected: u8, found: u8 },
    #[error("Key had a wrong length, expected {expected} but got {found}")]
    WrongLength { expected: usize, found: usize },
    #[error("Other decoding error: {0}")]
    Other(Box<dyn Error + Send + 'static>),
}

impl DecodingError {
    pub fn other<E: Error + Send + 'static>(error: E) -> DecodingError {
        DecodingError::Other(Box::new(error))
    }

    pub fn wrong_prefix(expected: u8, found: u8) -> DecodingError {
        DecodingError::WrongPrefix { expected, found }
    }

    pub fn wrong_length(expected: usize, found: usize) -> DecodingError {
        DecodingError::WrongLength { expected, found }
    }
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Underlying Database Error: {0}")]
    DbError(Box<dyn Error + Send>),
    #[error("Decoding error: {0}")]
    DecodingError(DecodingError),
}

impl From<DecodingError> for DatabaseError {
    fn from(e: DecodingError) -> Self {
        DatabaseError::DecodingError(e)
    }
}

impl<'a, T: Clone> BincodeSerialized<'a, T> {
    pub fn borrowed(obj: &'a T) -> BincodeSerialized<'a, T> {
        BincodeSerialized(Cow::Borrowed(obj))
    }

    pub fn owned(obj: T) -> BincodeSerialized<'static, T> {
        BincodeSerialized(Cow::Owned(obj))
    }

    pub fn into_owned(self) -> T {
        self.0.into_owned()
    }
}

impl<'a, T: Serialize + Debug + Clone> SerializableDatabaseValue for BincodeSerialized<'a, T> {
    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.0)
            .expect("Serialization error")
            .into()
    }
}

impl<'a, T: Serialize + Debug + DeserializeOwned + Clone> DatabaseValue
    for BincodeSerialized<'a, T>
{
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(BincodeSerialized(
            bincode::deserialize(&data).map_err(|e| DecodingError::other(e))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Database, DatabaseKey, DatabaseKeyPrefix, DatabaseValue, DecodingError, RawDatabase,
        SerializableDatabaseValue,
    };
    use std::sync::Arc;

    #[derive(Debug)]
    struct TestKey(u64);

    #[derive(Debug, Eq, PartialEq)]
    struct TestVal(u64);

    impl DatabaseKeyPrefix for TestKey {
        fn to_bytes(&self) -> Vec<u8> {
            self.0.to_be_bytes().to_vec()
        }
    }

    impl DatabaseKey for TestKey {
        fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(data);
            let num = u64::from_be_bytes(bytes);
            if num == 0 {
                Err(DecodingError::wrong_prefix(0, 0))
            } else {
                Ok(TestKey(num))
            }
        }
    }

    impl SerializableDatabaseValue for TestVal {
        fn to_bytes(&self) -> Vec<u8> {
            self.0.to_be_bytes().to_vec()
        }
    }

    impl DatabaseValue for TestVal {
        fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(data);
            let num = u64::from_be_bytes(bytes);
            if num == 0 {
                Err(DecodingError::wrong_prefix(0, 0))
            } else {
                Ok(TestVal(num))
            }
        }
    }

    pub fn test_db_impl(db: Arc<dyn RawDatabase + 'static>) {
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
        assert_eq!(db.get_value::<_, TestVal>(&TestKey(43)).unwrap(), None);

        db.insert_entry(&TestKey(42), &TestVal(3301)).unwrap();
        assert_eq!(db.get_value(&TestKey(42)).unwrap(), Some(TestVal(3301)));

        let removed = db.remove_entry::<_, TestVal>(&TestKey(42)).unwrap();
        assert_eq!(removed, Some(TestVal(3301)));
        assert_eq!(db.get_value::<_, TestVal>(&TestKey(42)).unwrap(), None);

        assert!(db
            .insert_entry(&TestKey(42), &TestVal(0))
            .unwrap()
            .is_none());
        assert!(db.get_value::<_, TestVal>(&TestKey(42)).is_err());
    }
}
