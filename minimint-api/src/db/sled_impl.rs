use core::future::Future;
use core::marker::Send;
use core::pin::Pin;
use std::ops::ControlFlow;

use super::{Database, DatabaseError, DecodingError, Transaction};
use async_trait::async_trait;
use futures::{
    future::LocalBoxFuture,
    stream::{self, LocalBoxStream},
    Stream,
};
use sled::transaction::TransactionError;
use tracing::{error, trace};

// TODO: maybe make the concrete impl its own crate
#[async_trait(?Send)]
impl Database for sled::Tree {
    async fn raw_insert_entry(
        &self,
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        Ok(self
            .insert(key, value)
            .map_err(|e| DatabaseError::DbError(Box::new(e)))?
            .map(|bytes| bytes.to_vec()))
    }

    async fn raw_get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        Ok(self
            .get(key)
            .map_err(|e| DatabaseError::DbError(Box::new(e)))?
            .map(|bytes| bytes.to_vec()))
    }

    async fn raw_remove_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        Ok(self
            .remove(key)
            .map_err(|e| DatabaseError::DbError(Box::new(e)))?
            .map(|bytes| bytes.to_vec()))
    }

    fn raw_find_by_prefix(
        &self,
        key_prefix: &[u8],
    ) -> LocalBoxStream<'_, Result<(Vec<u8>, Vec<u8>), DatabaseError>> {
        let iter = self.scan_prefix(key_prefix).map(|res| {
            res.map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()))
                .map_err(|e| DatabaseError::DbError(Box::new(e)))
        });
        Box::pin(stream::iter(iter))
    }

    fn raw_transaction<'a>(
        &'a self,
        f: &mut (dyn FnMut(&'a mut dyn Transaction) -> Pin<Box<dyn Future<Output = ()> + 'a>> + 'a),
    ) -> LocalBoxFuture<'a, Result<(), DatabaseError>> {
        todo!()
    }
}

impl From<DecodingError> for sled::transaction::ConflictableTransactionError<DecodingError> {
    fn from(e: DecodingError) -> Self {
        sled::transaction::ConflictableTransactionError::Abort(e)
    }
}

impl From<sled::Error> for DatabaseError {
    fn from(e: sled::Error) -> Self {
        DatabaseError::DbError(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[test_log::test]
    fn test_basic_rw() {
        let path = tempfile::Builder::new()
            .prefix("fcb-sled-test")
            .tempdir()
            .unwrap();
        let db = sled::open(path).unwrap();
        crate::db::tests::test_db_impl(Arc::new(db.open_tree("default").unwrap()));
    }
}
