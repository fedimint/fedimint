use super::batch::{BatchItem, DbBatch};
use super::Database;
use crate::db::PrefixIter;
use anyhow::Result;
use tracing::{error, trace};

impl Database for rocksdb::OptimisticTransactionDB {
    fn raw_insert_entry(&self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let val = self.get(key).unwrap();
        self.put(key, value)?;
        Ok(val)
    }

    fn raw_get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.get(key)?)
    }

    fn raw_remove_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let val = self.get(key).unwrap();
        self.delete(key)?;
        Ok(val)
    }

    fn raw_find_by_prefix(&self, key_prefix: &[u8]) -> PrefixIter<'_> {
        let prefix = key_prefix.to_vec();
        Box::new(
            self.prefix_iterator(prefix.clone())
                .map_while(move |res| {
                    let (key_bytes, value_bytes) = res.expect("DB error");
                    key_bytes
                        .starts_with(&prefix)
                        .then(|| (key_bytes, value_bytes))
                })
                .map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()))
                .map(Ok),
        )
    }

    fn raw_apply_batch(&self, batch: DbBatch) -> Result<()> {
        let batch: Vec<_> = batch.into();
        let tx = self.transaction();

        for change in batch.iter() {
            match change {
                BatchItem::InsertNewElement(element) => {
                    if tx.get(element.key.to_bytes()).unwrap().is_some() {
                        tx.put(element.key.to_bytes(), element.value.to_bytes())?;
                        error!("Database replaced element! This should not happen!");
                        trace!("Problematic key: {:?}", element.key);
                    } else {
                        tx.put(element.key.to_bytes(), element.value.to_bytes())?;
                    }
                }
                BatchItem::InsertElement(element) => {
                    tx.put(element.key.to_bytes(), element.value.to_bytes())?;
                }
                BatchItem::DeleteElement(key) => {
                    if tx.get(key.to_bytes()).unwrap().is_none() {
                        tx.delete(key.to_bytes())?;
                        error!("Database deleted absent element! This should not happen!");
                        trace!("Problematic key: {:?}", key);
                    } else {
                        tx.delete(key.to_bytes())?;
                    }
                }
                BatchItem::MaybeDeleteElement(key) => {
                    tx.delete(key.to_bytes())?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[test_log::test]
    fn test_basic_rw() {
        use rocksdb::{OptimisticTransactionDB, Options, SingleThreaded};

        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test")
            .tempdir()
            .unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db: OptimisticTransactionDB<SingleThreaded> =
            OptimisticTransactionDB::open_default(path).unwrap();

        crate::db::tests::test_db_impl(Arc::new(db));
    }
}
