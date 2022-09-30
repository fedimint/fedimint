//! Sled implementation of the `Database` trait. It should not be used anymore since it has known
//! issues and is unmaintained. Please use `rocksdb` instead.

use std::path::Path;

use anyhow::Result;
use fedimint_api::db::batch::{BatchItem, DbBatch};
use fedimint_api::db::IDatabase;
use fedimint_api::db::PrefixIter;
pub use sled;
use sled::transaction::TransactionError;
use tracing::error;

#[derive(Debug)]
pub struct SledDb(sled::Tree);

impl SledDb {
    pub fn open(db_path: impl AsRef<Path>, tree: &str) -> Result<SledDb, sled::Error> {
        let db = sled::open(db_path)?.open_tree(tree)?;
        Ok(SledDb(db))
    }

    pub fn inner(&self) -> &sled::Tree {
        &self.0
    }
}

impl From<sled::Tree> for SledDb {
    fn from(db: sled::Tree) -> Self {
        SledDb(db)
    }
}

impl From<SledDb> for sled::Tree {
    fn from(db: SledDb) -> Self {
        db.0
    }
}

// TODO: maybe make the concrete impl its own crate
impl IDatabase for SledDb {
    fn raw_insert_entry(&self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let ret = self.inner().insert(key, value)?.map(|bytes| bytes.to_vec());
        self.inner().flush().expect("DB failure");
        Ok(ret)
    }

    fn raw_get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .inner()
            .get(key)
            .map_err(anyhow::Error::from)?
            .map(|bytes| bytes.to_vec()))
    }

    fn raw_remove_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let ret = self
            .inner()
            .remove(key)
            .map_err(anyhow::Error::from)?
            .map(|bytes| bytes.to_vec());
        self.inner().flush().expect("DB failure");
        Ok(ret)
    }

    fn raw_find_by_prefix(&self, key_prefix: &[u8]) -> PrefixIter<'_> {
        Box::new(self.inner().scan_prefix(key_prefix).map(|res| {
            res.map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()))
                .map_err(anyhow::Error::from)
        }))
    }

    fn raw_apply_batch(&self, batch: DbBatch) -> Result<()> {
        let batch: Vec<_> = batch.into();

        let ret = self
            .inner()
            .transaction::<_, _, TransactionError>(|t| {
                for change in batch.iter() {
                    match change {
                        BatchItem::InsertNewElement(element) => {
                            if t.insert(element.key.to_bytes(), element.value.to_bytes())?
                                .is_some()
                            {
                                error!("Database replaced element! {:?}", element.key);
                            }
                        }
                        BatchItem::InsertElement(element) => {
                            t.insert(element.key.to_bytes(), element.value.to_bytes())?;
                        }
                        BatchItem::DeleteElement(key) => {
                            if t.remove(key.to_bytes())?.is_none() {
                                error!("Database deleted absent element! {:?}", key);
                            }
                        }
                        BatchItem::MaybeDeleteElement(key) => {
                            t.remove(key.to_bytes())?;
                        }
                    }
                }

                Ok(())
            })
            .map_err(anyhow::Error::from);
        self.inner().flush().expect("DB failure");
        ret
    }
}

#[cfg(test)]
mod tests {
    use crate::SledDb;
    #[test_log::test]
    fn test_basic_rw() {
        let path = tempfile::Builder::new()
            .prefix("fcb-sled-test")
            .tempdir()
            .unwrap();
        let db = SledDb::open(path, "default").unwrap();
        fedimint_api::db::test_db_impl(db.into());
    }
}
