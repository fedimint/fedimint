use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use anyhow::Context;
use bitvec::vec::BitVec;
use fedimint_core::{apply, async_trait_maybe_send};
use tokio::sync::futures::Notified;
use tokio::sync::Notify;

use super::{ISingleUseDatabaseTransaction, PrefixStream, Result};

/// Number of buckets used for `Notifications`.
const NOTIFY_BUCKETS: usize = 32;

/// The state of Notification.
///
/// This stores `NOTIFY_BUCKETS` number of `Notifies`.
/// Each key is assigned a bucket based on its hash value.
/// This will cause some false positives.
#[derive(Debug)]
pub struct Notifications {
    buckets: Vec<Notify>,
}

impl Default for Notifications {
    fn default() -> Self {
        Self {
            buckets: (0..NOTIFY_BUCKETS).map(|_| Notify::new()).collect(),
        }
    }
}

fn slot_index_for_hash(hash_value: u64) -> usize {
    (hash_value % (NOTIFY_BUCKETS as u64)) as usize
}

fn slot_index_for_key<K: Hash>(key: &K) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    let hash_value = hasher.finish();
    slot_index_for_hash(hash_value)
}

impl Notifications {
    pub fn new() -> Self {
        Self::default()
    }

    /// This registers for notification when called.
    ///
    /// Then waits for the notification when .awaited.
    ///
    /// NOTE: This may some false positives.
    pub fn register<K>(&self, key: &K) -> Notified
    where
        K: Hash,
    {
        self.buckets[slot_index_for_key(key)].notified()
    }

    /// Notify a key.
    ///
    /// All the waiters for this keys will be notified.
    pub async fn notify<K>(&self, key: &K)
    where
        K: Hash,
    {
        self.buckets[slot_index_for_key(key)].notify_waiters();
    }

    /// Notifies the waiters about the notifications recorded in NotifyQueue.
    pub fn submit_queue(&self, queue: NotifyQueue) {
        for bucket in queue.buckets.iter_ones() {
            self.buckets[bucket].notify_waiters();
        }
    }
}

/// Save notifications to be sent after transaction is complete.
#[derive(Debug)]
pub struct NotifyQueue {
    buckets: BitVec,
}

impl Default for NotifyQueue {
    fn default() -> Self {
        Self {
            buckets: BitVec::repeat(false, NOTIFY_BUCKETS),
        }
    }
}

impl NotifyQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add<K>(&mut self, key: &K)
    where
        K: Hash,
    {
        self.buckets.set(slot_index_for_key(key), true);
    }
}

/// Wrapper to implement `add_notification_key`
pub struct NotifyingTransaction<'a> {
    // TODO: try removing Box
    dbtx: Box<dyn ISingleUseDatabaseTransaction<'a>>,
    // notifications to be submitted after commit
    notify_queue: Option<NotifyQueue>,
    notifications: &'a Notifications,
}

impl<'a> NotifyingTransaction<'a> {
    pub fn new(
        dbtx: Box<dyn ISingleUseDatabaseTransaction<'a>>,
        notifications: &'a Notifications,
    ) -> Self {
        Self {
            dbtx,
            notify_queue: Some(NotifyQueue::new()),
            notifications,
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a> ISingleUseDatabaseTransaction<'a> for NotifyingTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        self.dbtx.raw_insert_bytes(key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.dbtx.raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.dbtx.raw_remove_entry(key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        self.dbtx.raw_find_by_prefix(key_prefix).await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        self.dbtx.raw_remove_by_prefix(key_prefix).await
    }

    async fn commit_tx(&mut self) -> Result<()> {
        self.dbtx.commit_tx().await?;
        self.notifications.submit_queue(
            self.notify_queue
                .take()
                .expect("commit must be called only once"),
        );
        Ok(())
    }

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        self.dbtx.rollback_tx_to_savepoint().await
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        self.dbtx.set_tx_savepoint().await
    }

    fn add_notification_key(&mut self, key: &[u8]) -> Result<()> {
        self.notify_queue
            .as_mut()
            .context("can not call add_notification_key after commit")?
            .add(&key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::db::test_utils::future_returns_shortly;

    use super::*;

    #[tokio::test]
    async fn test_notification_after_notify() {
        let notifs = Notifications::new();
        let key = 1;
        let sub = notifs.register(&key);
        notifs.notify(&key).await;
        assert!(future_returns_shortly(sub).await.is_some(), "should notify");
    }

    #[tokio::test]
    async fn test_no_notification_without_notify() {
        let notifs = Notifications::new();
        let key = 1;
        let sub = notifs.register(&key);
        assert!(
            future_returns_shortly(sub).await.is_none(),
            "should not notify"
        );
    }

    #[tokio::test]
    async fn test_multi() {
        let notifs = Notifications::new();
        let key1 = 1;
        let key2 = 2;
        let sub1 = notifs.register(&key1);
        let sub2 = notifs.register(&key2);
        notifs.notify(&key1).await;
        notifs.notify(&key2).await;
        assert!(
            future_returns_shortly(sub1).await.is_some(),
            "should notify"
        );
        assert!(
            future_returns_shortly(sub2).await.is_some(),
            "should notify"
        );
    }

    #[tokio::test]
    async fn test_notify_queue() {
        let notifs = Notifications::new();
        let key1 = 1;
        let key2 = 2;
        let sub1 = notifs.register(&key1);
        let sub2 = notifs.register(&key2);
        let mut queue = NotifyQueue::new();
        queue.add(&key1);
        queue.add(&key2);
        notifs.submit_queue(queue);
        assert!(
            future_returns_shortly(sub1).await.is_some(),
            "should notify"
        );
        assert!(
            future_returns_shortly(sub2).await.is_some(),
            "should notify"
        );
    }
}
