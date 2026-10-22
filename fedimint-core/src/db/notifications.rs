use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

/// Exact-key notifications, retaining only keys with active registrations.
///
/// A tree releases its nodes as registrations disappear, unlike a hash table
/// whose capacity can retain a historical high-water mark.
#[derive(Debug, Default)]
pub struct Notifications {
    keys: Mutex<BTreeMap<Vec<u8>, Entry>>,
}

#[derive(Debug)]
struct Entry {
    notify: Arc<Notify>,
    registrations: usize,
}

/// Keeps the entry alive even when the returned future has not been polled.
struct Registration<'a> {
    notifications: &'a Notifications,
    key: Vec<u8>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        let mut keys = self.notifications.keys.lock().expect("lock poisoned");
        let entry = keys.get_mut(&self.key).expect("registration owns an entry");
        entry.registrations -= 1;
        if entry.registrations == 0 {
            keys.remove(&self.key);
        }
    }
}

impl Notifications {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register synchronously, then wait for the next update when awaited.
    ///
    /// `notified_owned` observes `notify_waiters` from its creation, even
    /// before its first poll. Create it under the registry lock so a
    /// notification cannot slip between finding the entry and arming the
    /// wait. The caller must register before taking its database snapshot.
    pub fn register(&self, key: &[u8]) -> impl Future<Output = ()> + Send + use<'_> {
        let mut keys = self.keys.lock().expect("lock poisoned");
        let entry = keys.entry(key.to_vec()).or_insert_with(|| Entry {
            notify: Arc::new(Notify::new()),
            registrations: 0,
        });
        entry.registrations += 1;
        let notified = entry.notify.clone().notified_owned();
        let registration = Registration {
            notifications: self,
            key: key.to_vec(),
        };
        drop(keys);

        async move {
            notified.await;
            drop(registration);
        }
    }

    /// Notify all registrations for exactly this key.
    pub fn notify(&self, key: &[u8]) {
        let notify = self
            .keys
            .lock()
            .expect("lock poisoned")
            .get(key)
            .map(|entry| entry.notify.clone());
        // Waking a task may execute its waker inline. Do not hold the registry
        // lock while waking, since cancellation/registration also takes it.
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
    }

    /// Deliver notifications only after the database transaction commits.
    pub fn submit_queue(&self, queue: &NotifyQueue) {
        if let Some(buckets) = queue.buckets {
            let notifies: Vec<_> = self
                .keys
                .lock()
                .expect("lock poisoned")
                .iter()
                .filter(|(key, _)| buckets & bucket_mask(key) != 0)
                .map(|(_, entry)| entry.notify.clone())
                .collect();
            for notify in notifies {
                notify.notify_waiters();
            }
        } else {
            for key in &queue.keys {
                self.notify(key);
            }
        }
    }
}

/// Bound exact-key bookkeeping for large write batches and unusually large
/// keys.
/// Keep small commits (including single-key signed session outcomes) precise,
/// without allocating a key per write in bulk transactions.
const MAX_EXACT_KEYS: usize = 8;
const MAX_EXACT_KEY_BYTES: usize = 512;

fn bucket_mask(key: &[u8]) -> u32 {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    1 << (hasher.finish() % 32)
}

/// Keys changed by a transaction, deduplicated until commit.
///
/// Keep keys, not the current subscriptions: a waiter can register after a
/// write is queued but before it commits, and must observe that commit too.
/// Large batches fall back to the former 32-bucket notification scheme,
/// bounding queue memory at the cost of false-positive wakes for those
/// transactions.
#[derive(Debug, Default)]
pub struct NotifyQueue {
    keys: BTreeSet<Vec<u8>>,
    key_bytes: usize,
    buckets: Option<u32>,
}

impl NotifyQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, key: &[u8]) {
        if let Some(buckets) = &mut self.buckets {
            *buckets |= bucket_mask(key);
            return;
        }
        if self.keys.contains(key) {
            return;
        }
        if self.keys.len() == MAX_EXACT_KEYS || key.len() > MAX_EXACT_KEY_BYTES - self.key_bytes {
            self.buckets = Some(
                self.keys
                    .iter()
                    .fold(bucket_mask(key), |mask, key| mask | bucket_mask(key)),
            );
            self.keys.clear();
            self.key_bytes = 0;
            return;
        }
        self.key_bytes += key.len();
        self.keys.insert(key.to_vec());
    }
}

#[cfg(test)]
mod tests;
