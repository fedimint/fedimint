use crate::encoding::{Decodable, Encodable};
use batch::DbBatch;
use std::error::Error;
use std::fmt::Debug;
use std::marker::PhantomData;
use thiserror::Error;
use tracing::trace;

pub mod batch;
pub mod mem_impl;
pub mod sled_impl;

pub trait DatabaseKeyPrefixConst {
    const DB_PREFIX: u8;
}

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

pub type PrefixIter = Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>), DatabaseError>> + Send>;

pub trait Database: Send + Sync {
    fn raw_insert_entry(
        &self,
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, DatabaseError>;

    fn raw_get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError>;

    fn raw_remove_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError>;

    fn raw_find_by_prefix(&self, key_prefix: &[u8]) -> PrefixIter;

    fn raw_apply_batch(&self, batch: DbBatch) -> Result<(), DatabaseError>;
}

pub struct DbIter<K, V>
where
    K: DatabaseKey,
    V: DatabaseValue,
{
    iter: PrefixIter,
    _pd: PhantomData<(K, V)>,
}

impl<'a> dyn Database + 'a {
    pub fn insert_entry<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        match self.raw_insert_entry(&key.to_bytes(), value.to_bytes())? {
            Some(old_val_bytes) => {
                trace!(
                    "insert_entry: Decoding {} from bytes {:?}",
                    std::any::type_name::<V>(),
                    old_val_bytes
                );
                Ok(Some(V::from_bytes(&old_val_bytes)?))
            }
            None => Ok(None),
        }
    }

    pub fn get_value<K, V>(&self, key: &K) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_get_value(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        trace!(
            "get_value: Decoding {} from bytes {:?}",
            std::any::type_name::<V>(),
            value_bytes
        );
        Ok(Some(V::from_bytes(&value_bytes)?))
    }

    pub fn remove_entry<K, V>(&self, key: &K) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_remove_entry(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        trace!(
            "remove_entry: Decoding {} from bytes {:?}",
            std::any::type_name::<V>(),
            value_bytes
        );
        Ok(Some(V::from_bytes(&value_bytes)?))
    }

    pub fn find_by_prefix<KP, K, V>(&self, key_prefix: &KP) -> DbIter<K, V>
    where
        KP: DatabaseKeyPrefix,
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let prefix_bytes = key_prefix.to_bytes();
        DbIter {
            iter: self.raw_find_by_prefix(&prefix_bytes),
            _pd: Default::default(),
        }
    }

    pub fn apply_batch(&self, batch: DbBatch) -> Result<(), DatabaseError> {
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

                trace!(
                    "db iter: Decoding {} from bytes {:?}",
                    std::any::type_name::<V>(),
                    value_bytes
                );
                let value = match V::from_bytes(value_bytes.as_ref()) {
                    Ok(value) => value,
                    Err(e) => return Some(Err(e.into())),
                };
                Some(Ok((key, value)))
            }
            Err(e) => Some(Err(e)),
        }
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

        <Self as crate::encoding::Decodable>::consensus_decode(std::io::Cursor::new(&data[1..]))
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
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        T::consensus_decode(std::io::Cursor::new(data)).map_err(|e| DecodingError::Other(e.0))
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

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::db::DatabaseKeyPrefixConst;
    use crate::encoding::{Decodable, Encodable};
    use std::sync::Arc;

    #[derive(Debug, Encodable, Decodable)]
    struct TestKey(u64);

    impl DatabaseKeyPrefixConst for TestKey {
        const DB_PREFIX: u8 = 0x42;
    }

    #[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
    struct TestVal(u64);

    pub fn test_db_impl(db: Arc<dyn Database + 'static>) {
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
        assert!(db.get_value::<_, TestVal>(&TestKey(42)).is_ok());
    }
}
