use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll};

use futures::task::{ArcWake, waker};
use futures::{FutureExt, poll};

use super::{MAX_EXACT_KEY_BYTES, MAX_EXACT_KEYS, Notifications, NotifyQueue, bucket_mask};

#[test]
fn notification_before_first_poll() {
    let notifications = Notifications::new();
    let first = notifications.register(b"key");
    let second = notifications.register(b"key");
    notifications.notify(b"key");
    assert_eq!(first.now_or_never(), Some(()));
    assert_eq!(second.now_or_never(), Some(()));
    assert!(notifications.keys.lock().unwrap().is_empty());
}

#[tokio::test]
async fn exact_keys_and_multiple_registrations() {
    let notifications = Notifications::new();
    let first = notifications.register(b"key");
    let second = notifications.register(b"key");
    let other = notifications.register(b"other");
    let prefixed = notifications.register(b"prefix/key");
    tokio::pin!(first, second, other, prefixed);
    assert_eq!(poll!(&mut first), Poll::Pending);
    assert_eq!(poll!(&mut second), Poll::Pending);
    notifications.notify(b"key");
    assert_eq!(poll!(&mut first), Poll::Ready(()));
    assert_eq!(poll!(&mut second), Poll::Ready(()));
    assert_eq!(poll!(&mut other), Poll::Pending);
    assert_eq!(poll!(&mut prefixed), Poll::Pending);
}

#[test]
fn cancelled_registration_does_not_remove_other_waiters() {
    let notifications = Notifications::new();
    let first = notifications.register(b"key");
    let second = notifications.register(b"key");
    drop(first);
    assert_eq!(notifications.keys.lock().unwrap().len(), 1);
    notifications.notify(b"key");
    assert_eq!(second.now_or_never(), Some(()));
    assert!(notifications.keys.lock().unwrap().is_empty());
    let next = notifications.register(b"key");
    assert_eq!(next.now_or_never(), None);
    assert!(notifications.keys.lock().unwrap().is_empty());
}

#[test]
fn queue_includes_late_registrations_and_deduplicates_keys() {
    let notifications = Notifications::new();
    let mut queue = NotifyQueue::new();
    queue.add(b"key");
    queue.add(b"key");
    assert_eq!(queue.keys.len(), 1);
    let late = notifications.register(b"key");
    let other = notifications.register(b"other");
    notifications.submit_queue(&queue);
    assert_eq!(late.now_or_never(), Some(()));
    assert_eq!(other.now_or_never(), None);
}

#[test]
fn historical_keys_are_not_retained() {
    let notifications = Notifications::new();
    for key in 0_u64..10_000 {
        let wait = notifications.register(&key.to_le_bytes());
        drop(wait);
        notifications.notify(&key.to_le_bytes());
        assert!(notifications.keys.lock().unwrap().is_empty());
    }
    let waits: Vec<_> = (0_u64..1_000)
        .map(|key| notifications.register(&key.to_le_bytes()))
        .collect();
    assert_eq!(notifications.keys.lock().unwrap().len(), waits.len());
    drop(waits);
    assert!(notifications.keys.lock().unwrap().is_empty());
}

/// A bounded fanout measurement: one changed key completes one of 4096
/// registrations, rather than waking all keys sharing one of 32 buckets.
#[test]
fn unrelated_keys_do_not_complete() {
    let notifications = Notifications::new();
    let waits: Vec<_> = (0_u64..4096)
        .map(|key| notifications.register(&key.to_le_bytes()))
        .collect();
    notifications.notify(&42_u64.to_le_bytes());
    let completed = waits
        .into_iter()
        .filter_map(FutureExt::now_or_never)
        .count();
    assert_eq!(completed, 1);
    assert!(notifications.keys.lock().unwrap().is_empty());

    // Reproduce the old bucket assignment on exactly the same keys.
    let bucket = |key: u64| {
        let mut hasher = DefaultHasher::new();
        key.to_le_bytes().as_slice().hash(&mut hasher);
        hasher.finish() % 32
    };
    let old_completed = (0..4096).filter(|key| bucket(*key) == bucket(42)).count();
    assert!(old_completed > completed);
    println!("4096 registered keys, one update: old={old_completed}, exact={completed}");
}

#[test]
fn concurrent_registration_notification_and_cancellation() {
    let notifications = Notifications::new();
    let barrier = Barrier::new(8);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for round in 0_u64..500 {
                    let key = round.to_le_bytes();
                    let wait = notifications.register(&key);
                    let cancelled = notifications.register(&key);
                    drop(cancelled);
                    barrier.wait();
                    notifications.notify(&key);
                    assert_eq!(wait.now_or_never(), Some(()));
                    barrier.wait();
                }
            });
        }
    });
    assert!(notifications.keys.lock().unwrap().is_empty());
}

struct RegisterOnWake(Arc<Notifications>);

impl ArcWake for RegisterOnWake {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        // An inline waker can re-enter the registry, including drop cleanup.
        drop(arc_self.0.register(b"reentrant"));
    }
}

#[test]
fn wake_does_not_hold_registry_lock() {
    let notifications = Arc::new(Notifications::new());
    let waker = waker(Arc::new(RegisterOnWake(notifications.clone())));
    let mut context = Context::from_waker(&waker);
    let mut wait = Box::pin(notifications.register(b"key"));
    assert!(wait.as_mut().poll(&mut context).is_pending());
    notifications.notify(b"key");
    assert!(wait.as_mut().poll(&mut context).is_ready());
    assert!(notifications.keys.lock().unwrap().is_empty());

    let mut wait = Box::pin(notifications.register(b"key"));
    assert!(wait.as_mut().poll(&mut context).is_pending());
    let mut queue = NotifyQueue::new();
    queue.add(&vec![0; MAX_EXACT_KEY_BYTES + 1]);
    queue.add(b"key");
    notifications.submit_queue(&queue);
    assert!(wait.as_mut().poll(&mut context).is_ready());
    assert!(notifications.keys.lock().unwrap().is_empty());
}

#[test]
fn large_queue_retains_all_changed_buckets_but_not_keys() {
    let notifications = Notifications::new();
    let mut queue = NotifyQueue::new();
    let keys: Vec<_> = (0..MAX_EXACT_KEYS + 2).map(usize::to_le_bytes).collect();
    for key in &keys {
        queue.add(key);
    }
    assert!(queue.keys.is_empty());
    assert_eq!(queue.key_bytes, 0);
    assert_eq!(
        queue.buckets,
        Some(keys.iter().fold(0, |mask, key| mask | bucket_mask(key)))
    );
    // All subscriptions join after the writes, including keys from before,
    // during and after the switch to buckets.
    let waits: Vec<_> = keys.iter().map(|key| notifications.register(key)).collect();
    notifications.submit_queue(&queue);
    for wait in waits {
        assert_eq!(wait.now_or_never(), Some(()));
    }
    assert!(notifications.keys.lock().unwrap().is_empty());
}

#[test]
fn queue_limits_bytes_and_preserves_unmatched_bucket_isolation() {
    let notifications = Notifications::new();
    let mut queue = NotifyQueue::new();
    let key = vec![42; MAX_EXACT_KEY_BYTES + 1];
    queue.add(&key);
    assert!(queue.keys.is_empty());
    assert_eq!(queue.key_bytes, 0);
    assert_eq!(queue.buckets, Some(bucket_mask(&key)));
    let unrelated = (0_u64..1024)
        .map(u64::to_le_bytes)
        .find(|other| bucket_mask(other) != bucket_mask(&key))
        .unwrap();
    let changed = notifications.register(&key);
    let other = notifications.register(&unrelated);
    notifications.submit_queue(&queue);
    assert_eq!(changed.now_or_never(), Some(()));
    assert_eq!(other.now_or_never(), None);
}

#[test]
fn exact_queue_limits_include_duplicates_and_total_bytes() {
    let mut queue = NotifyQueue::new();
    let first = vec![1; MAX_EXACT_KEY_BYTES / 2];
    let second = vec![2; MAX_EXACT_KEY_BYTES / 2];
    queue.add(&first);
    queue.add(&second);
    queue.add(&first);
    assert_eq!(queue.key_bytes, MAX_EXACT_KEY_BYTES);
    assert_eq!(queue.keys.len(), 2);
    assert!(queue.buckets.is_none());
    queue.add(b"overflow");
    assert!(queue.keys.is_empty());
    assert_eq!(
        queue.buckets,
        Some(bucket_mask(&first) | bucket_mask(&second) | bucket_mask(b"overflow"))
    );
}

/// Run explicitly in release mode. This measures notification bookkeeping, not
/// database throughput. Keep the old algorithm here only as a comparison.
#[test]
#[ignore = "bounded notification microbenchmark"]
fn notification_bookkeeping_microbenchmark() {
    use std::hint::black_box;

    use bitvec::vec::BitVec;
    use tokio::sync::Notify;

    use crate::time::now;

    const TRANSACTIONS: usize = 10_000;

    let old_bucket = |key: &[u8]| {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() % 32) as usize
    };
    let old_notifications: Vec<_> = (0..32).map(|_| Notify::new()).collect();
    let notifications = Notifications::new();
    for writes in [1, 8, 9, 128, 4096] {
        let keys: Vec<_> = (0_u64..writes).map(u64::to_le_bytes).collect();
        let start = now();
        for _ in 0..TRANSACTIONS {
            let mut buckets: BitVec = BitVec::repeat(false, 32);
            for key in &keys {
                buckets.set(old_bucket(black_box(key)), true);
            }
            for bucket in buckets.iter_ones() {
                old_notifications[bucket].notify_waiters();
            }
        }
        let old = now().duration_since(start).unwrap();
        let start = now();
        for _ in 0..TRANSACTIONS {
            let mut queue = NotifyQueue::new();
            for key in &keys {
                queue.add(black_box(key));
            }
            notifications.submit_queue(&queue);
        }
        let exact = now().duration_since(start).unwrap();
        println!(
            "no waiters, {TRANSACTIONS} transactions x {writes} distinct 8-byte keys: \
             old={old:?}, bounded={exact:?}"
        );
    }

    let start = now();
    for _ in 0..TRANSACTIONS {
        let wait = old_notifications[old_bucket(b"key")].notified();
        old_notifications[old_bucket(b"key")].notify_waiters();
        assert_eq!(black_box(wait).now_or_never(), Some(()));
    }
    let old = now().duration_since(start).unwrap();
    let start = now();
    for _ in 0..TRANSACTIONS {
        let wait = notifications.register(black_box(b"key"));
        notifications.notify(black_box(b"key"));
        assert_eq!(black_box(wait).now_or_never(), Some(()));
    }
    println!(
        "{TRANSACTIONS} register/notify/complete cycles on one key: \
         old={old:?}, exact={:?}",
        now().duration_since(start).unwrap()
    );
}
