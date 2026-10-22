use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use assert_matches::assert_matches;
use macro_rules_attribute::apply;
use tokio::sync::Notify;

use crate::async_trait_maybe_send;
use crate::db::mem_impl::{MemDatabase, MemTransaction};
use crate::db::{
    DatabaseError, DatabaseKeyPrefix, DatabaseResult, IDatabaseTransactionOpsCoreTyped,
    IRawDatabase, IRawDatabaseExt, TestKey, TestVal,
};

#[derive(Debug, Default)]
struct SnapshotPause {
    armed: AtomicBool,
    resume: Notify,
}

#[tokio::test]
async fn commit_only_notifications_across_clones_and_prefixes() {
    let global = MemDatabase::new().into_database();
    let module = global.with_prefix_module_id(2).0;
    let other_module = global.with_prefix_module_id(3).0;
    let writer_db = module.clone();
    let key = TestKey(1);
    let bytes = key.to_bytes();
    let mut global_wait = global.inner.register(&bytes).await;
    let mut other_wait = other_module.inner.register(&bytes).await;
    let mut module_wait = module.inner.register(&bytes).await;
    let mut same_key_wait = module.inner.register(&bytes).await;
    let mut different_key_wait = module.inner.register(&TestKey(2).to_bytes()).await;

    let mut discarded = writer_db.begin_transaction().await;
    discarded.insert_entry(&key, &TestVal(1)).await;
    discarded.ignore_uncommitted();
    drop(discarded);
    assert!(futures::poll!(module_wait.as_mut()).is_pending());
    assert_eq!(
        module.begin_transaction_nc().await.get_value(&key).await,
        None
    );

    let mut writer = writer_db.begin_transaction().await;
    writer.insert_entry(&key, &TestVal(42)).await;
    assert!(futures::poll!(module_wait.as_mut()).is_pending());
    // A registration made after the write must also receive its commit.
    let mut late_wait = module.inner.register(&bytes).await;
    writer.commit_tx().await;
    assert!(futures::poll!(module_wait.as_mut()).is_ready());
    assert!(futures::poll!(same_key_wait.as_mut()).is_ready());
    assert!(futures::poll!(late_wait.as_mut()).is_ready());
    assert!(futures::poll!(global_wait.as_mut()).is_pending());
    assert!(futures::poll!(other_wait.as_mut()).is_pending());
    assert!(futures::poll!(different_key_wait.as_mut()).is_pending());

    let mut removal_wait = module.inner.register(&bytes).await;
    let mut writer = writer_db.begin_transaction().await;
    writer.remove_entry(&key).await;
    assert!(futures::poll!(removal_wait.as_mut()).is_pending());
    writer.commit_tx().await;
    assert!(futures::poll!(removal_wait.as_mut()).is_ready());
}

#[tokio::test]
async fn failed_commit_does_not_notify() {
    check_failed_commit(false).await;
    check_failed_commit(true).await;
}

async fn check_failed_commit(large_batch: bool) {
    let db = MemDatabase::new().into_database();
    let key = TestKey(1);
    let mut loser = db.begin_transaction().await;
    loser.insert_entry(&key, &TestVal(1)).await;
    if large_batch {
        for index in 2..130 {
            loser.insert_entry(&TestKey(index), &TestVal(index)).await;
        }
    }
    let mut winner = db.begin_transaction().await;
    winner.insert_entry(&key, &TestVal(2)).await;
    winner.commit_tx().await;

    let mut wait = db.inner.register(&key.to_bytes()).await;
    assert_matches!(
        loser.commit_tx_result().await,
        Err(DatabaseError::WriteConflict)
    );
    assert!(futures::poll!(wait.as_mut()).is_pending());
    assert_eq!(
        db.begin_transaction_nc().await.get_value(&key).await,
        Some(TestVal(2))
    );
}

#[tokio::test]
async fn large_batch_notifies_late_registration_only_after_commit() {
    let db = MemDatabase::new()
        .into_database()
        .with_prefix_module_id(2)
        .0;
    let mut writer = db.begin_transaction().await;
    for index in 0..128 {
        writer.insert_entry(&TestKey(index), &TestVal(index)).await;
    }
    let mut waits = Vec::new();
    for index in [0, 64, 127] {
        waits.push(db.inner.register(&TestKey(index).to_bytes()).await);
    }
    for wait in &mut waits {
        assert!(futures::poll!(wait.as_mut()).is_pending());
    }
    writer.commit_tx().await;
    for wait in &mut waits {
        assert!(futures::poll!(wait.as_mut()).is_ready());
    }
}

#[tokio::test]
async fn unrelated_commits_do_not_recheck_waiters() {
    for module_id in [None, Some(2)] {
        let db = MemDatabase::new().into_database();
        let db = match module_id {
            Some(id) => db.with_prefix_module_id(id).0,
            None => db,
        };
        let keys: Vec<_> = (0..4096).map(TestKey).collect();
        let checks = std::cell::Cell::new(0);
        let mut waits: Vec<_> = keys
            .iter()
            .map(|key| {
                Box::pin(db.wait_key_check(key, |value| {
                    checks.set(checks.get() + 1);
                    value
                }))
            })
            .collect();
        for wait in &mut waits {
            assert!(futures::poll!(wait.as_mut()).is_pending());
        }
        assert_eq!(checks.replace(0), keys.len());
        let mut writer = db.begin_transaction().await;
        writer.insert_entry(&TestKey(42), &TestVal(42)).await;
        writer.commit_tx().await;
        let mut completed = 0;
        for wait in &mut waits {
            if futures::poll!(wait.as_mut()).is_ready() {
                completed += 1;
            }
        }
        assert_eq!(completed, 1);
        // Each checker invocation follows a fresh snapshot and key read.
        println!(
            "4096 DB waiters, module={module_id:?}: {} rechecks",
            checks.get()
        );
        assert_eq!(checks.get(), 1);
    }
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
