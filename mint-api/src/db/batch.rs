use super::{DatabaseKeyPrefix, SerializableDatabaseValue};

pub type DbBatch = Accumulator<BatchItem>;
pub type BatchTx<'a> = AccumulatorTx<'a, BatchItem>;

#[derive(Debug)]
/// Database key-value pair
pub struct Element {
    pub key: Box<dyn DatabaseKeyPrefix + Send>,
    pub value: Box<dyn SerializableDatabaseValue + Send>,
}

#[derive(Debug)]
/// Database operation
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

/// Collects a batch of items of type `T` over its lifetime and supports transactions to return
/// to a previous state in case of failure.
///
/// It is used to collect [`BatchItem`]s from all consensus modules that will be committed at the
/// end of processing the epoch's output. Transactions are used when items should already be
/// accumulated optimistically while it is still unclear if the consensus item is valid. In case
/// it turns out to be invalid the accumulator can be reset to its previous state.
///
/// Resetting happens automatically when a [`AccumulatorTx`] is dropped after going out of scope.
/// To prevent this from happening [`AccumulatorTx::commit`] should be called before.
pub struct Accumulator<T> {
    buffer: Vec<T>,
}

/// A transaction on an [`Accumulator`] that aborts by default when dropped unless `commit` is
/// called previously.
pub struct AccumulatorTx<'a, T> {
    batch: &'a mut Accumulator<T>,
    checkpoint: usize,
}

impl<T> Accumulator<T> {
    /// Construct a new, empty `Accumulator`
    pub fn new() -> Accumulator<T> {
        Accumulator { buffer: Vec::new() }
    }

    /// Start a new transaction. If the [`AccumulatorTx`] is dropped without [`AccumulatorTx::commit`]
    /// being called the accumulator does not change (is reset to the state of the transaction start
    /// internally).
    pub fn transaction(&mut self) -> AccumulatorTx<T> {
        let last_commit = self.buffer.len();
        AccumulatorTx {
            batch: self,
            checkpoint: last_commit,
        }
    }

    /// Shortcut to just append some items to the batch without the option to abort
    pub fn autocommit<F>(&mut self, f: F)
    where
        F: FnOnce(&mut AccumulatorTx<T>),
    {
        let mut tx = self.transaction();
        f(&mut tx);
        tx.commit();
    }
}

impl<'a, T> AccumulatorTx<'a, T> {
    /// Commit the current accumulator state
    pub fn commit(self) {
        std::mem::forget(self);
    }

    /// Append one `item` to the pending transaction
    pub fn append(&mut self, item: T) {
        self.batch.buffer.push(item);
    }

    /// Append multiple items to the pending transaction
    pub fn append_from_iter(&mut self, iter: impl Iterator<Item = T>) {
        self.batch.buffer.extend(iter);
    }

    /// Start a sub-transaction which has the following behavior:
    ///  * Aborting the sub-transaction does not automatically abort the parent transaction but
    ///    only resets the parent transaction to the state when the sub-transaction was created.
    ///  * Committing a sub-transaction makes its changes part of the parent transaction. Note that
    ///    the parent transaction may still be aborted leading to the removal of sub-transaction
    ///    items.
    pub fn subtransaction<'b, 'c>(&'b mut self) -> AccumulatorTx<'c, T>
    where
        'a: 'b,
        'b: 'c,
    {
        let checkpoint = self.batch.buffer.len();
        AccumulatorTx::<'c, T> {
            batch: self.batch,
            checkpoint,
        }
    }

    /// Currently the accumulator and transactions are not thread safe. Therefore one has to create
    /// at least one accumulator per thread when parallelizing. This function can be used to merge
    /// these with a minimal amount of allocations.
    pub fn append_from_accumulators(&mut self, iter: impl Iterator<Item = Accumulator<T>>) {
        self.append_from_iter(iter.flat_map(|acc| acc.buffer))
    }

    /// Allocate space for items to avoid frequent reallocation
    pub fn reserve(&mut self, items: usize) {
        self.batch.buffer.reserve(items);
    }
}

impl<'a, T> Drop for AccumulatorTx<'a, T> {
    fn drop(&mut self) {
        self.batch.buffer.truncate(self.checkpoint);
    }
}

impl<T> From<Accumulator<T>> for Vec<T> {
    fn from(acc: Accumulator<T>) -> Self {
        acc.buffer
    }
}

impl BatchItem {
    /// Construct a DB operation to insert a new element
    pub fn insert_new<K, V>(key: K, value: V) -> Self
    where
        K: DatabaseKeyPrefix + Send + 'static,
        V: SerializableDatabaseValue + Send + 'static,
    {
        BatchItem::InsertNewElement(Element::new(key, value))
    }

    /// Construct a DB operation to insert a potentially already existing item
    pub fn insert<K, V>(key: K, value: V) -> Self
    where
        K: DatabaseKeyPrefix + Send + 'static,
        V: SerializableDatabaseValue + Send + 'static,
    {
        BatchItem::InsertElement(Element::new(key, value))
    }

    /// Construct a DB operation to delete an existing element
    pub fn delete<K>(key: K) -> Self
    where
        K: DatabaseKeyPrefix + Send + 'static,
    {
        BatchItem::DeleteElement(Box::new(key))
    }

    /// Construct a DB operation to delete a potentially absent element
    pub fn maybe_delete<K>(key: K) -> Self
    where
        K: DatabaseKeyPrefix + Send + 'static,
    {
        BatchItem::MaybeDeleteElement(Box::new(key))
    }
}

impl<'a> AccumulatorTx<'a, BatchItem> {
    /// Append a DB operation to insert a new element
    pub fn append_insert_new<K, V>(&mut self, key: K, value: V)
    where
        K: DatabaseKeyPrefix + Send + 'static,
        V: SerializableDatabaseValue + Send + 'static,
    {
        self.append(BatchItem::insert_new(key, value))
    }

    /// Append a DB operation to insert a potentially already existing item
    pub fn append_insert<K, V>(&mut self, key: K, value: V)
    where
        K: DatabaseKeyPrefix + Send + 'static,
        V: SerializableDatabaseValue + Send + 'static,
    {
        self.append(BatchItem::insert(key, value))
    }

    /// Append a DB operation to delete an existing element
    pub fn append_delete<K>(&mut self, key: K)
    where
        K: DatabaseKeyPrefix + Send + 'static,
    {
        self.append(BatchItem::delete(key))
    }

    /// Append a DB operation to delete a potentially absent element
    pub fn append_maybe_delete<K>(&mut self, key: K)
    where
        K: DatabaseKeyPrefix + Send + 'static,
    {
        self.append(BatchItem::maybe_delete(key))
    }
}

#[cfg(test)]
mod test {
    use super::Accumulator;

    #[test]
    fn test_transaction() {
        let mut acc = Accumulator::<u8>::new();
        {
            let mut tx = acc.transaction();
            tx.append(1);
        }
        assert!(Vec::<u8>::from(acc).is_empty());

        let mut acc = Accumulator::<u8>::new();
        {
            let mut tx = acc.transaction();
            tx.append(1);
            tx.append(2);
            tx.append(3);
            tx.commit();
        }
        assert_eq!(Vec::<u8>::from(acc), vec![1, 2, 3]);

        let mut acc = Accumulator::<u8>::new();
        {
            let mut tx = acc.transaction();
            tx.append(1);
            tx.commit();
        }
        {
            let mut tx = acc.transaction();
            tx.append(2);
            tx.append(3);
        }
        assert_eq!(Vec::<u8>::from(acc), vec![1]);
    }
}
