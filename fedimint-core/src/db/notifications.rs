use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use bitvec::vec::BitVec;
use tokio::sync::Notify;
use tokio::sync::futures::Notified;

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

fn slot_index_for_key<K: Hash>(key: K) -> usize {
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
    pub fn register<K>(&self, key: K) -> Notified
    where
        K: Hash,
    {
        self.buckets[slot_index_for_key(key)].notified()
    }

    /// Notify a key.
    ///
    /// All the waiters for this keys will be notified.
    pub fn notify<K>(&self, key: K)
    where
        K: Hash,
    {
        self.buckets[slot_index_for_key(key)].notify_waiters();
    }

    /// Notifies the waiters about the notifications recorded in `NotifyQueue`.
    pub fn submit_queue(&self, queue: &NotifyQueue) {
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

#[cfg(test)]
mod tests;
