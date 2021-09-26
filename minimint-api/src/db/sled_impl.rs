use super::batch::{BatchItem, DbBatch};
use super::{DatabaseError, DecodingError, RawDatabase};
use sled::transaction::TransactionError;
use tracing::{error, trace};

// TODO: maybe make the concrete impl its own crate
impl RawDatabase for sled::Tree {
    fn raw_insert_entry(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        Ok(self
            .insert(key, value)
            .map_err(|e| DatabaseError::DbError(Box::new(e)))?
            .map(|bytes| bytes.to_vec()))
    }

    fn raw_get_value(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, DatabaseError> {
        Ok(self
            .get(key)
            .map_err(|e| DatabaseError::DbError(Box::new(e)))?
            .map(|bytes| bytes.to_vec()))
    }

    fn raw_remove_entry(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, DatabaseError> {
        Ok(self
            .remove(key)
            .map_err(|e| DatabaseError::DbError(Box::new(e)))?
            .map(|bytes| bytes.to_vec()))
    }

    fn raw_find_by_prefix(
        &self,
        key_prefix: Vec<u8>,
    ) -> Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>), DatabaseError>>> {
        Box::new(self.scan_prefix(key_prefix).map(|res| {
            res.map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()))
                .map_err(|e| DatabaseError::DbError(Box::new(e)))
        }))
    }

    fn raw_apply_batch(&self, batch: DbBatch) -> Result<(), DatabaseError> {
        let batch: Vec<_> = batch.into();

        self.transaction(|t| {
            for change in batch.iter() {
                match change {
                    BatchItem::InsertNewElement(element) => {
                        if t.insert(element.key.to_bytes(), element.value.to_bytes())?
                            .is_some()
                        {
                            error!("Database replaced element! This should not happen!");
                            trace!("Problematic key: {:?}", element.key);
                        }
                    }
                    BatchItem::InsertElement(element) => {
                        t.insert(element.key.to_bytes(), element.value.to_bytes())?;
                    }
                    BatchItem::DeleteElement(key) => {
                        if t.remove(key.to_bytes())?.is_none() {
                            error!("Database deleted absent element! This should not happen!");
                            trace!("Problematic key: {:?}", key);
                        }
                    }
                    BatchItem::MaybeDeleteElement(key) => {
                        t.remove(key.to_bytes())?;
                    }
                }
            }

            Ok(())
        })
        .map_err(|e: TransactionError| DatabaseError::DbError(Box::new(e)))
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

    #[test]
    fn test_basic_rw() {
        let path = tempdir::TempDir::new("fcb-sled-test").unwrap();
        let db = sled::open(path).unwrap();
        crate::db::tests::test_db_impl(Arc::new(db.open_tree("default").unwrap()));
    }
}
