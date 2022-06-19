use crate::encoding::{Decodable, Encodable};
use async_trait::async_trait;
use futures::stream::LocalBoxStream;
use futures::{Stream, StreamExt};
use std::error::Error;
use std::fmt::Debug;
use std::future::Future;
use std::ops::ControlFlow;
use std::pin::Pin;
use thiserror::Error;
use tracing::trace;

pub mod batch;
pub mod mem_impl;
pub mod sled_impl;

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
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError>;
}

#[async_trait(?Send)]
pub trait Transaction {
    async fn raw_insert_entry(
        &self,
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, DatabaseError>;

    async fn raw_get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError>;

    async fn raw_remove_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError>;

    async fn raw_find_by_prefix(
        &self,
        key_prefix: &[u8],
        cb: &mut dyn FnMut(Result<(Vec<u8>, Vec<u8>), DatabaseError>) -> ControlFlow<()>,
    );
}

#[async_trait(?Send)]
pub trait Database: Send + Sync {
    async fn raw_insert_entry(
        &self,
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, DatabaseError>;

    async fn raw_get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError>;

    async fn raw_remove_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError>;

    fn raw_find_by_prefix(
        &self,
        key_prefix: &[u8],
    ) -> LocalBoxStream<'_, Result<(Vec<u8>, Vec<u8>), DatabaseError>>;

    async fn raw_transaction<'a>(
        &'a self,
        f: &mut (dyn FnMut(Box<dyn Transaction>) -> Pin<Box<dyn Future<Output = ()> + 'a>> + 'a),
    ) -> Result<(), DatabaseError>;
}

impl<'a> dyn Database + 'a {
    pub async fn insert_entry<K>(
        &self,
        key: &K,
        value: &K::Value,
    ) -> Result<Option<K::Value>, DatabaseError>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        match self
            .raw_insert_entry(&key.to_bytes(), value.to_bytes())
            .await?
        {
            Some(old_val_bytes) => {
                trace!(
                    "insert_entry: Decoding {} from bytes {:?}",
                    std::any::type_name::<K::Value>(),
                    old_val_bytes
                );
                Ok(Some(K::Value::from_bytes(&old_val_bytes)?))
            }
            None => Ok(None),
        }
    }

    pub async fn get_value<K>(&self, key: &K) -> Result<Option<K::Value>, DatabaseError>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_get_value(&key_bytes).await? {
            Some(value) => value,
            None => return Ok(None),
        };

        trace!(
            "get_value: Decoding {} from bytes {:?}",
            std::any::type_name::<K::Value>(),
            value_bytes
        );
        Ok(Some(K::Value::from_bytes(&value_bytes)?))
    }

    pub async fn remove_entry<K>(&self, key: &K) -> Result<Option<K::Value>, DatabaseError>
    where
        K: DatabaseKey + DatabaseKeyPrefixConst,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.raw_remove_entry(&key_bytes).await? {
            Some(value) => value,
            None => return Ok(None),
        };

        trace!(
            "remove_entry: Decoding {} from bytes {:?}",
            std::any::type_name::<K::Value>(),
            value_bytes
        );
        Ok(Some(K::Value::from_bytes(&value_bytes)?))
    }

    pub fn find_by_prefix<KP>(
        &self,
        key_prefix: &KP,
    ) -> impl Stream<Item = Result<(KP::Key, KP::Value), DatabaseError>> + '_
    where
        KP: DatabaseKeyPrefix + DatabaseKeyPrefixConst,
    {
        let prefix_bytes = key_prefix.to_bytes();

        let stream = self.raw_find_by_prefix(&prefix_bytes);
        stream.map(|res| {
            let (key_bytes, value_bytes) = res?;
            let key = KP::Key::from_bytes(&key_bytes)?;
            trace!(
                "find by prefix: Decoding {} from bytes {:?}",
                std::any::type_name::<KP::Value>(),
                value_bytes
            );
            let value = KP::Value::from_bytes(&value_bytes)?;
            Ok((key, value))
        })
    }

    pub async fn transaction<'s, F: Future<Output = ()> + 's>(
        &self,
        cb: impl FnOnce(Box<dyn Transaction>) -> F,
    ) -> Result<(), DatabaseError> {
        let mut cb = Some(cb);
        self.raw_transaction(&mut |tr| {
            let cb = cb
                .take()
                .expect("raw_transaction callback called more than once");
            Box::pin((cb)(tr))
        })
        .await
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
        type Key = Self;
        type Value = TestVal;
    }

    #[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
    struct TestVal(u64);

    pub fn test_db_impl(db: Arc<dyn Database + 'static>) {
        todo!()
    }
}
