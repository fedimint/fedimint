use crate::{Database, DatabaseError, DatabaseKey, DatabaseValue};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct MemDatabase {
    data: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DummyError;

impl MemDatabase {
    pub fn new() -> MemDatabase {
        Default::default()
    }
}

impl Database for MemDatabase {
    fn insert_entry<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let old = self
            .data
            .lock()
            .unwrap()
            .insert(key.to_bytes(), value.to_bytes())
            .map(|old_value| V::from_bytes(&old_value))
            .transpose()?;

        Ok(old)
    }

    fn get_value<K, V>(&self, key: &K) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let value = self
            .data
            .lock()
            .unwrap()
            .get(&key.to_bytes())
            .map(|value| V::from_bytes(&value))
            .transpose()?;

        Ok(value)
    }

    fn remove_entry<K, V>(&self, key: &K) -> Result<Option<V>, DatabaseError>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let old = self
            .data
            .lock()
            .unwrap()
            .remove(&key.to_bytes())
            .map(|old_value| V::from_bytes(&old_value))
            .transpose()?;

        Ok(old)
    }
}

#[cfg(test)]
mod tests {
    use crate::mem_impl::MemDatabase;

    #[test]
    fn test_basic_rw() {
        let mem_db = MemDatabase::new();
        crate::tests::test_db_impl(&mem_db);
    }
}
