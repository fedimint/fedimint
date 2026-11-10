use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use assert_matches::assert_matches;
use macro_rules_attribute::apply;
use tokio::sync::Notify;

use crate::async_trait_maybe_send;
use crate::db::mem_impl::{MemDatabase, MemTransaction};
use crate::db::{
    DatabaseResult, IDatabaseTransactionOpsCoreTyped, IRawDatabase, IRawDatabaseExt, TestKey,
    TestVal,
};
use crate::task::TaskGroup;

#[derive(Debug, Default)]
struct SnapshotPause {
    armed: AtomicBool,
    resume: Notify,
}

/// Preserve normal database notifications, but allow a writer to commit after
/// the waiter's snapshot is taken and before that snapshot is read.
#[derive(Debug)]
struct PausedSnapshotDatabase {
    inner: MemDatabase,
    pause: Arc<SnapshotPause>,
}

#[apply(async_trait_maybe_send!)]
impl IRawDatabase for PausedSnapshotDatabase {
    type Transaction<'a> = MemTransaction<'a>;

    async fn begin_transaction<'a>(&'a self) -> Self::Transaction<'a> {
        let snapshot = self.inner.begin_transaction().await;
        if self.pause.armed.swap(false, Ordering::SeqCst) {
            self.pause.resume.notified().await;
        }
        snapshot
    }

    fn checkpoint(&self, path: &std::path::Path) -> DatabaseResult<()> {
        self.inner.checkpoint(path)
    }
}

async fn commit_during_snapshot(module_id: Option<u16>, updates: &[u64]) {
    let pause = Arc::new(SnapshotPause::default());
    let db = PausedSnapshotDatabase {
        inner: MemDatabase::new(),
        pause: pause.clone(),
    }
    .into_database();
    let db = match module_id {
        Some(id) => db.with_prefix_module_id(id).0,
        None => db,
    };
    let key = TestKey(1);
    let waiter = db.wait_key_check(&key, |value| value.filter(|value| *value == TestVal(42)));
    futures::pin_mut!(waiter);

    // Poll exactly to the snapshot pause, then commit on the same Database.
    // No scheduler timing or wall-clock timeout is needed to force the race.
    pause.armed.store(true, Ordering::SeqCst);
    assert!(futures::poll!(waiter.as_mut()).is_pending());
    assert!(!pause.armed.load(Ordering::SeqCst));

    for value in updates {
        let mut writer = db.begin_transaction().await;
        writer.insert_entry(&key, &TestVal(*value)).await;
        writer.commit_tx().await;
        pause.resume.notify_one();

        if *value == 42 {
            assert_matches!(
                futures::poll!(waiter.as_mut()),
                std::task::Poll::Ready((TestVal(42), _)),
                "waiter must observe the commit even though its earlier snapshot is stale"
            );
        } else {
            assert!(futures::poll!(waiter.as_mut()).is_pending());
        }
    }
}

#[tokio::test]
async fn commit_between_snapshot_and_wait() {
    commit_during_snapshot(None, &[42]).await;
}

#[tokio::test]
async fn module_commit_between_snapshot_and_wait() {
    commit_during_snapshot(Some(2), &[42]).await;
}

#[tokio::test]
async fn wait_again_after_unsatisfied_updates() {
    commit_during_snapshot(None, &[1, 2, 42]).await;
    commit_during_snapshot(Some(2), &[1, 2, 42]).await;
}

#[test]
fn send_checker_does_not_need_sync() {
    fn assert_send(_: impl crate::task::MaybeSend) {}

    let db = MemDatabase::new().into_database();
    let key = TestKey(1);
    let checks = std::cell::Cell::new(0);
    assert_send(db.wait_key_check(&key, move |value| {
        checks.set(checks.get() + 1);
        value
    }));
    let group = TaskGroup::new();
    let checks = std::cell::Cell::new(0);
    assert_send(db.wait_key_check_with_shutdown(
        &key,
        move |value| {
            checks.set(checks.get() + 1);
            value
        },
        group.make_handle().make_shutdown_rx(),
    ));
}

#[tokio::test]
async fn registration_remembers_updates_before_wait_is_polled() {
    for module_id in [None, Some(2)] {
        let db = MemDatabase::new().into_database();
        let db = match module_id {
            Some(id) => db.with_prefix_module_id(id).0,
            None => db,
        };
        // Registration must not retain the temporary key, including through
        // the module-prefix wrapper.
        let mut notification = {
            let key = [1];
            db.inner.register(&key).await
        };
        db.inner.notify(&[1]).await;
        assert!(futures::poll!(notification.as_mut()).is_ready());

        // A new registration must wait for a new notification.
        let mut notification = db.inner.register(&[1]).await;
        assert!(futures::poll!(notification.as_mut()).is_pending());
        drop(notification);

        // Cancelling one wait must not prevent subsequent subscriptions.
        let mut notification = db.inner.register(&[1]).await;
        assert!(futures::poll!(notification.as_mut()).is_pending());
        db.inner.notify(&[1]).await;
        assert!(futures::poll!(notification.as_mut()).is_ready());
    }
}

#[tokio::test]
async fn shutdown_before_wait_does_not_check_even_an_existing_key() {
    let db = MemDatabase::new().into_database();
    let key = TestKey(1);
    let mut tx = db.begin_transaction().await;
    tx.insert_entry(&key, &TestVal(42)).await;
    tx.commit_tx().await;
    let group = TaskGroup::new();
    group.shutdown();

    assert!(
        db.wait_key_check_with_shutdown(
            &key,
            |_| -> Option<()> { panic!("must not check after shutdown") },
            group.make_handle().make_shutdown_rx(),
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn shutdown_cancels_waiters_without_closing_database() {
    for module_id in [None, Some(2)] {
        let db = MemDatabase::new().into_database();
        let db = match module_id {
            Some(id) => db.with_prefix_module_id(id).0,
            None => db,
        };
        let db_clone = db.clone();
        let key = TestKey(1);
        let group = TaskGroup::new();
        let other_group = TaskGroup::new();
        let first = db.wait_key_exists_with_shutdown(&key, group.make_handle().make_shutdown_rx());
        let second =
            db_clone.wait_key_exists_with_shutdown(&key, group.make_handle().make_shutdown_rx());
        let independent =
            db.wait_key_exists_with_shutdown(&key, other_group.make_handle().make_shutdown_rx());
        futures::pin_mut!(first, second, independent);
        assert!(futures::poll!(first.as_mut()).is_pending());
        assert!(futures::poll!(second.as_mut()).is_pending());
        assert!(futures::poll!(independent.as_mut()).is_pending());

        group.shutdown();
        assert_matches!(
            futures::poll!(first.as_mut()),
            std::task::Poll::Ready(Err(_))
        );
        assert_matches!(
            futures::poll!(second.as_mut()),
            std::task::Poll::Ready(Err(_))
        );
        assert!(futures::poll!(independent.as_mut()).is_pending());

        let mut tx = db.begin_transaction().await;
        tx.insert_entry(&key, &TestVal(42)).await;
        tx.commit_tx().await;
        assert_eq!(independent.await.unwrap(), TestVal(42));
        assert_eq!(db.wait_key_exists(&key).await, TestVal(42));
    }
}

#[tokio::test]
async fn shutdown_while_acquiring_snapshot() {
    let pause = Arc::new(SnapshotPause::default());
    let db = PausedSnapshotDatabase {
        inner: MemDatabase::new(),
        pause: pause.clone(),
    }
    .into_database();
    let group = TaskGroup::new();
    let key = TestKey(1);
    let waiter = db.wait_key_exists_with_shutdown(&key, group.make_handle().make_shutdown_rx());
    futures::pin_mut!(waiter);
    pause.armed.store(true, Ordering::SeqCst);
    assert!(futures::poll!(waiter.as_mut()).is_pending());
    assert!(!pause.armed.load(Ordering::SeqCst));
    group.shutdown();
    // The backend never resumes, but shutdown must still finish the wait.
    assert_matches!(
        futures::poll!(waiter.as_mut()),
        std::task::Poll::Ready(Err(_))
    );
}

#[tokio::test]
async fn shutdown_aware_wait_preserves_checker_and_snapshot() {
    let db = MemDatabase::new().into_database();
    let group = TaskGroup::new();
    let key = TestKey(1);
    // Cell also verifies that a Send checker does not need Sync.
    let checks = std::cell::Cell::new(0);
    let waiter = db.wait_key_check_with_shutdown(
        &key,
        |value| {
            checks.set(checks.get() + 1);
            value.filter(|value| *value == TestVal(42))
        },
        group.make_handle().make_shutdown_rx(),
    );
    futures::pin_mut!(waiter);
    assert!(futures::poll!(waiter.as_mut()).is_pending());
    for value in [1, 42] {
        let mut tx = db.begin_transaction().await;
        tx.insert_entry(&key, &TestVal(value)).await;
        tx.commit_tx().await;
        if value == 1 {
            assert!(futures::poll!(waiter.as_mut()).is_pending());
        }
    }
    let (value, mut snapshot) = waiter.await.unwrap();
    assert_eq!(value, TestVal(42));
    assert_eq!(checks.get(), 3);
    let mut tx = db.begin_transaction().await;
    tx.insert_entry(&key, &TestVal(43)).await;
    tx.commit_tx().await;
    assert_eq!(snapshot.get_value(&key).await, Some(TestVal(42)));
}
