use crate::batch::BatchItem;
use std::error::Error;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use thiserror::Error;

pub mod batch;
pub mod sled_impl;

pub trait DatabaseKeyPrefix {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait DatabaseKey: Sized + DatabaseKeyPrefix {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError>;
}

pub trait SerializableDatabaseValue {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait DatabaseValue: Sized + SerializableDatabaseValue {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError>;
}

pub trait Database {
    type Err: Error + From<DecodingError>;

    fn insert_entry<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseKey,
        V: DatabaseValue;

    fn get_value<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseKey,
        V: DatabaseValue;

    fn remove_entry<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseKey,
        V: DatabaseValue;
}

pub trait PrefixSearchable: Database {
    type Bytes: AsRef<[u8]>;
    type IterErr: Error + Into<DatabaseError>;
    type Iter: Iterator<Item = Result<(Self::Bytes, Self::Bytes), Self::IterErr>>;

    fn find_by_prefix<KP, K, V>(
        &self,
        key_prefix: &KP,
    ) -> DbIter<Self::Iter, Self::Bytes, Self::IterErr, K, V>
    where
        KP: DatabaseKeyPrefix,
        K: DatabaseKey,
        V: DatabaseValue;
}

pub trait Transactional: Database {
    type TransactionError: Error;
    type Transaction: Database;

    // FIXME: don't rely on sled here, doing it properly requires GATs though, maybe some other
    // trick like getting rid of E and A and pinning them to () would be preferable in the meantime
    fn transaction<F, A>(&self, f: F) -> Result<A, Self::TransactionError>
    where
        F: Fn(&Self::Transaction) -> Result<A, <Self::Transaction as Database>::Err>;
}

pub trait BatchDb: Database {
    fn apply_batch<B>(&self, batch: B) -> Result<(), DatabaseError>
    where
        B: IntoIterator<Item = BatchItem>;
}

pub struct DbIter<Iter, Bytes, IterErr, K, V>
where
    Iter: Iterator<Item = Result<(Bytes, Bytes), IterErr>>,
    Bytes: AsRef<[u8]>,
    IterErr: Into<DatabaseError>,
    K: DatabaseKey,
    V: DatabaseValue,
{
    iter: Iter,
    _pd: PhantomData<(K, V)>,
}

impl<Iter, Bytes, IterErr, K, V> Iterator for DbIter<Iter, Bytes, IterErr, K, V>
where
    Iter: Iterator<Item = Result<(Bytes, Bytes), IterErr>>,
    Bytes: AsRef<[u8]>,
    IterErr: Into<DatabaseError>,
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
            Err(DecodingError("Expected zero bytes for empty tuple".into()))
        }
    }
}

#[derive(Debug, Error)]
pub struct DecodingError(pub Box<dyn Error>);

impl Display for DecodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Underlying Database Error: {0}")]
    DbError(Box<dyn Error>),
    #[error("Decoding error: {0}")]
    DecodingError(DecodingError),
}

impl From<DecodingError> for DatabaseError {
    fn from(e: DecodingError) -> Self {
        DatabaseError::DecodingError(e)
    }
}
