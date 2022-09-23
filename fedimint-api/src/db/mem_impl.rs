use super::batch::{BatchItem, DbBatch};
use super::IDatabase;
use crate::db::PrefixIter;
use anyhow::Result;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use tracing::error;

#[derive(Debug, Default, Clone)]
pub struct MemDatabase {
    data: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DummyError;

impl MemDatabase {
    pub fn new() -> MemDatabase {
        Default::default()
    }

    pub fn dump_db(&self) {
        let data = self.data.lock().unwrap();
        let data_iter = data.iter();
        for (key, value) in data_iter {
            eprintln!("{}: {}", hex::encode(key), hex::encode(value));
        }
    }
}

impl IDatabase for MemDatabase {
    fn raw_insert_entry(&self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        Ok(self.data.lock().unwrap().insert(key.to_vec(), value))
    }

    fn raw_get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.data.lock().unwrap().get(key).cloned())
    }

    fn raw_remove_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.data.lock().unwrap().remove(key))
    }

    fn raw_find_by_prefix(&self, key_prefix: &[u8]) -> PrefixIter<'_> {
        let mut data = self
            .data
            .lock()
            .unwrap()
            .range::<Vec<u8>, _>((key_prefix.to_vec())..)
            .take_while(|(key, _)| key.starts_with(key_prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        data.reverse();

        Box::new(MemDbIter { data })
    }

    fn raw_apply_batch(&self, batch: DbBatch) -> Result<()> {
        let batch: Vec<_> = batch.into();

        for change in batch.iter() {
            match change {
                BatchItem::InsertNewElement(element) => {
                    if self
                        .raw_insert_entry(&element.key.to_bytes(), element.value.to_bytes())?
                        .is_some()
                    {
                        error!("Database replaced element! {:?}", element.key);
                    }
                }
                BatchItem::InsertElement(element) => {
                    self.raw_insert_entry(&element.key.to_bytes(), element.value.to_bytes())?;
                }
                BatchItem::DeleteElement(key) => {
                    if self.raw_remove_entry(&key.to_bytes())?.is_none() {
                        error!("Database deleted absent element! {:?}", key);
                    }
                }
                BatchItem::MaybeDeleteElement(key) => {
                    self.raw_remove_entry(&key.to_bytes())?;
                }
            }
        }

        Ok(())
    }
}

struct MemDbIter {
    data: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Iterator for MemDbIter {
    type Item = Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.data.pop().map(Result::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::MemDatabase;

    #[test_log::test]
    fn test_basic_rw() {
        let mem_db = MemDatabase::new();
        crate::db::tests::test_db_impl(mem_db.into());
    }
}
