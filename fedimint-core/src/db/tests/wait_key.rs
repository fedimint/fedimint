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
