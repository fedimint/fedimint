use serde::__private::Formatter;
use sled::transaction::TransactionResult;
use sled::IVec;
use std::error::Error;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use thiserror::Error;

pub trait DatabaseEncode {
    fn to_bytes(&self) -> IVec;
}

pub trait DatabaseDecode: Sized {
    fn from_bytes(data: &IVec) -> Result<Self, DecodingError>;
}

pub trait Database {
    type Err: Error + From<DecodingError>;

    fn insert_entry<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseEncode + DatabaseDecode,
        V: DatabaseEncode + DatabaseDecode;

    fn get_value<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseEncode,
        V: DatabaseEncode + DatabaseDecode;

    fn remove_entry<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseEncode,
        V: DatabaseEncode + DatabaseDecode;
}

pub trait PrefixSearchable: Database {
    type IterErr: Error + Into<DatabaseError>;
    type Iter: Iterator<Item = Result<(IVec, IVec), Self::IterErr>>;

    fn find_by_prefix<KP, K, V>(&self, key_prefix: &KP) -> DbIter<Self::Iter, Self::IterErr, K, V>
    where
        KP: DatabaseEncode,
        K: DatabaseEncode + DatabaseDecode,
        V: DatabaseEncode + DatabaseDecode;
}

pub trait Transactional: Database {
    type Transaction: Database<Err = sled::transaction::ConflictableTransactionError<DecodingError>>;

    // FIXME: don't rely on sled here, doing it properly requires GATs though, maybe some other
    // trick like getting rid of E and A and pinning them to () would be preferable in the meantime
    fn transaction<F, A>(&self, f: F) -> sled::transaction::TransactionResult<A, DecodingError>
    where
        F: Fn(
            &Self::Transaction,
        ) -> sled::transaction::ConflictableTransactionResult<A, DecodingError>;
}

pub struct DbIter<Iter, IterErr, K, V>
where
    Iter: Iterator<Item = Result<(IVec, IVec), IterErr>>,
    IterErr: Into<DatabaseError>,
    K: DatabaseEncode + DatabaseDecode,
    V: DatabaseEncode + DatabaseDecode,
{
    iter: Iter,
    _pd: PhantomData<(K, V)>,
}

impl Database for sled::transaction::TransactionalTree {
    type Err = sled::transaction::ConflictableTransactionError<DecodingError>;

    fn insert_entry<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseEncode + DatabaseDecode,
        V: DatabaseEncode + DatabaseDecode,
    {
        match self.insert(key.to_bytes(), value.to_bytes())? {
            Some(old_val_bytes) => Ok(Some(V::from_bytes(&old_val_bytes)?)),
            None => Ok(None),
        }
    }

    fn get_value<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseEncode,
        V: DatabaseEncode + DatabaseDecode,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.get(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(V::from_bytes(&value_bytes)?))
    }

    fn remove_entry<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseEncode,
        V: DatabaseEncode + DatabaseDecode,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.remove(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(V::from_bytes(&value_bytes)?))
    }
}

impl Database for sled::Tree {
    type Err = DatabaseError;

    fn insert_entry<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseEncode + DatabaseDecode,
        V: DatabaseEncode + DatabaseDecode,
    {
        match self.insert(key.to_bytes(), value.to_bytes())? {
            Some(old_val_bytes) => Ok(Some(V::from_bytes(&old_val_bytes)?)),
            None => Ok(None),
        }
    }

    fn get_value<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseEncode,
        V: DatabaseEncode + DatabaseDecode,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.get(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(V::from_bytes(&value_bytes)?))
    }

    fn remove_entry<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseEncode,
        V: DatabaseEncode + DatabaseDecode,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.remove(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(V::from_bytes(&value_bytes)?))
    }
}

impl PrefixSearchable for sled::Tree {
    type IterErr = sled::Error;
    type Iter = sled::Iter;

    fn find_by_prefix<KP, K, V>(&self, key_prefix: &KP) -> DbIter<Self::Iter, Self::IterErr, K, V>
    where
        KP: DatabaseEncode,
        V: DatabaseEncode + DatabaseDecode,
        K: DatabaseEncode + DatabaseDecode,
    {
        let prefix_bytes = key_prefix.to_bytes();
        DbIter {
            iter: self.scan_prefix(&prefix_bytes),
            _pd: Default::default(),
        }
    }
}

impl Transactional for sled::Tree {
    type Transaction = sled::transaction::TransactionalTree;

    fn transaction<F, A>(&self, f: F) -> TransactionResult<A, DecodingError>
    where
        F: Fn(
            &Self::Transaction,
        ) -> sled::transaction::ConflictableTransactionResult<A, DecodingError>,
    {
        self.transaction(f)
    }
}

impl<Iter, IterErr, K, V> Iterator for DbIter<Iter, IterErr, K, V>
where
    Iter: Iterator<Item = Result<(IVec, IVec), IterErr>>,
    IterErr: Into<DatabaseError>,
    K: DatabaseEncode + DatabaseDecode,
    V: DatabaseEncode + DatabaseDecode,
{
    type Item = Result<(K, V), DatabaseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next()? {
            Ok((key_bytes, value_bytes)) => {
                let key = match K::from_bytes(&key_bytes) {
                    Ok(key) => key,
                    Err(e) => return Some(Err(e.into())),
                };
                let value = match V::from_bytes(&value_bytes) {
                    Ok(value) => value,
                    Err(e) => return Some(Err(e.into())),
                };
                Some(Ok((key, value)))
            }
            Err(e) => Some(Err(e.into())),
        }
    }
}

impl DatabaseEncode for () {
    fn to_bytes(&self) -> IVec {
        vec![].into()
    }
}

impl DatabaseDecode for () {
    fn from_bytes(data: &IVec) -> Result<Self, DecodingError> {
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
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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

impl From<DecodingError> for sled::transaction::ConflictableTransactionError<DecodingError> {
    fn from(e: DecodingError) -> Self {
        sled::transaction::ConflictableTransactionError::Abort(e)
    }
}

impl From<sled::Error> for DatabaseError {
    fn from(e: sled::Error) -> Self {
        DatabaseError::DbError(e.into())
    }
}
