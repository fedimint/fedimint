use super::batch::{BatchItem, DbBatch};
use super::{Database, DecodingError};
use crate::db::PrefixIter;
use anyhow::Result;
use sled::transaction::TransactionError;
use tracing::{error, trace};

// TODO: maybe make the concrete impl its own crate
impl Database for sled::Tree {
    fn raw_insert_entry(&self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        Ok(self.insert(key, value)?.map(|bytes| bytes.to_vec()))
    }

    fn raw_get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .get(key)
            .map_err(anyhow::Error::from)?
            .map(|bytes| bytes.to_vec()))
    }

    fn raw_remove_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .remove(key)
            .map_err(anyhow::Error::from)?
            .map(|bytes| bytes.to_vec()))
    }

    fn raw_find_by_prefix(&self, key_prefix: &[u8]) -> PrefixIter<'_> {
        Box::new(self.scan_prefix(key_prefix).map(|res| {
            res.map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()))
                .map_err(anyhow::Error::from)
        }))
    }

    fn raw_apply_batch(&self, batch: DbBatch) -> Result<()> {
        let batch: Vec<_> = batch.into();

        self.transaction::<_, _, TransactionError>(|t| {
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
        .map_err(anyhow::Error::from)
    }
}

impl From<DecodingError> for sled::transaction::ConflictableTransactionError<DecodingError> {
    fn from(e: DecodingError) -> Self {
        sled::transaction::ConflictableTransactionError::Abort(e)
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
