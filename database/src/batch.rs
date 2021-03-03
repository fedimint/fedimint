use crate::{DatabaseKeyPrefix, SerializableDatabaseValue};

pub type Batch = Vec<BatchItem>;

pub struct Element {
    pub key: Box<dyn DatabaseKeyPrefix + Send>,
    pub value: Box<dyn SerializableDatabaseValue + Send>,
}

pub enum BatchItem {
    /// Inserts element, errors if it already exists
    InsertNewElement(Element),
    /// Insets new element, even if it already exists
    InsertElement(Element),
    /// Deletes element, errors if it doesn't exist
    DeleteElement(Box<dyn DatabaseKeyPrefix + Send>),
    /// Deletes element, does nothing if it doesn't exist
    MaybeDeleteElement(Box<dyn DatabaseKeyPrefix + Send>),
}

impl Element {
    pub fn new<K, V>(key: K, value: V) -> Element
    where
        K: DatabaseKeyPrefix + Send + 'static,
        V: SerializableDatabaseValue + Send + 'static,
    {
        Element {
            key: Box::new(key),
            value: Box::new(value),
        }
    }
}
