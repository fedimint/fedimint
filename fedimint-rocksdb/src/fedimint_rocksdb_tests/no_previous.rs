use fedimint_core::db::{
    DatabaseError, IDatabaseTransactionOpsCore, IRawDatabase, IRawDatabaseTransaction,
};

use super::super::{RocksDb, RocksDbReadOnly};

async fn write(tx: &mut impl IDatabaseTransactionOpsCore, no_previous: bool, delete: bool) {
    match (no_previous, delete) {
        (false, false) => {
            tx.raw_insert_bytes(b"key", b"new").await.unwrap();
        }
        (false, true) => {
            tx.raw_remove_entry(b"key").await.unwrap();
        }
        (true, false) => tx
            .raw_insert_bytes_no_previous(b"key", b"new")
            .await
            .unwrap(),
        (true, true) => tx.raw_remove_entry_no_previous(b"key").await.unwrap(),
    }
}

#[derive(Clone, Copy)]
struct ConflictCase {
    initial: bool,
    delete: bool,
    rival_delete: bool,
    schedule: u8,
}

async fn conflict_case(no_previous: bool, case: ConflictCase) -> (bool, Option<Vec<u8>>) {
    let ConflictCase {
        initial,
        delete,
        rival_delete,
        schedule,
    } = case;
    let path = tempfile::tempdir().unwrap();
    let db = RocksDb::build(path.path()).open_blocking().unwrap();
    if initial {
        let mut seed = db.begin_transaction().await;
        seed.raw_insert_bytes(b"key", &[]).await.unwrap();
        seed.commit_tx().await.unwrap();
    }
    if schedule == 0 {
        let mut rival = db.begin_transaction().await;
        write(&mut rival, false, rival_delete).await;
        rival.commit_tx().await.unwrap();
    }
    let mut tx = db.begin_transaction().await;
    let snapshot = tx.raw_get_bytes(b"key").await.unwrap();
    if schedule == 2 {
        write(&mut tx, no_previous, delete).await;
    }
    if schedule != 0 {
        let mut rival = db.begin_transaction().await;
        write(&mut rival, false, rival_delete).await;
        rival.commit_tx().await.unwrap();
    }
    if schedule != 2 {
        // Both paths must see the same original snapshot after a concurrent
        // commit, even when their first write occurs after that commit.
        assert_eq!(tx.raw_get_bytes(b"key").await.unwrap(), snapshot);
        write(&mut tx, no_previous, delete).await;
    }
    assert_eq!(
        tx.raw_get_bytes(b"key").await.unwrap(),
        if delete { None } else { Some(b"new".to_vec()) }
    );
    let conflict = match tx.commit_tx().await {
        Ok(()) => false,
        Err(DatabaseError::WriteConflict) => true,
        Err(other) => panic!("Unexpected commit error: {other}"),
    };
    assert_eq!(conflict, schedule != 0);
    let value = db
        .begin_transaction()
        .await
        .raw_get_bytes(b"key")
        .await
        .unwrap();
    (conflict, value)
}

#[tokio::test(flavor = "multi_thread")]
async fn no_previous_conflicts_match_legacy() {
    for initial in [false, true] {
        for delete in [false, true] {
            for rival_delete in [false, true] {
                for schedule in 0..3 {
                    let case = ConflictCase {
                        initial,
                        delete,
                        rival_delete,
                        schedule,
                    };
                    assert_eq!(
                        conflict_case(false, case).await,
                        conflict_case(true, case).await,
                        "initial={initial} delete={delete} rival_delete={rival_delete} schedule={schedule}"
                    );
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_previous_savepoint_and_rollback_match_legacy() {
    for no_previous in [false, true] {
        let path = tempfile::tempdir().unwrap();
        let db = RocksDb::build(path.path()).open_blocking().unwrap();
        let mut tx = db.begin_transaction().await;
        tx.0.set_savepoint();
        write(&mut tx, no_previous, false).await;
        write(&mut tx, no_previous, true).await;
        tx.0.rollback_to_savepoint().unwrap();
        assert_eq!(tx.raw_get_bytes(b"key").await.unwrap(), None);
        let mut rival = db.begin_transaction().await;
        write(&mut rival, false, false).await;
        rival.commit_tx().await.unwrap();
        // Rolled-back writes must not leave a conflict-tracking entry.
        tx.commit_tx().await.unwrap();
        let mut tx = db.begin_transaction().await;
        tx.0.set_savepoint();
        write(&mut tx, no_previous, true).await;
        tx.0.rollback_to_savepoint().unwrap();
        assert_eq!(
            tx.raw_get_bytes(b"key").await.unwrap(),
            Some(b"new".to_vec())
        );
        write(&mut tx, no_previous, true).await;
        tx.0.rollback().unwrap();
        drop(tx);
        assert_eq!(
            db.begin_transaction()
                .await
                .raw_get_bytes(b"key")
                .await
                .unwrap(),
            Some(b"new".to_vec())
        );
        let mut tx = db.begin_transaction().await;
        tx.raw_insert_bytes_no_previous(&[], &[0, 255])
            .await
            .unwrap();
        let large_key = vec![7; 65536];
        let large_value = vec![8; 65536];
        tx.raw_insert_bytes_no_previous(&large_key, &large_value)
            .await
            .unwrap();
        tx.commit_tx().await.unwrap();
        let mut tx = db.begin_transaction().await;
        assert_eq!(tx.raw_get_bytes(&[]).await.unwrap(), Some(vec![0, 255]));
        assert_eq!(
            tx.raw_get_bytes(&large_key).await.unwrap(),
            Some(large_value)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_previous_read_only_still_rejects_writes() {
    use std::panic::AssertUnwindSafe;

    use futures::FutureExt;

    let path = tempfile::tempdir().unwrap();
    drop(RocksDb::build(path.path()).open_blocking().unwrap());
    let db = RocksDbReadOnly::open_read_only(path.path()).await.unwrap();
    let mut tx = db.begin_transaction().await;
    assert!(
        AssertUnwindSafe(tx.raw_insert_bytes_no_previous(b"k", b"v"))
            .catch_unwind()
            .await
            .is_err()
    );
    assert!(
        AssertUnwindSafe(tx.raw_remove_entry_no_previous(b"k"))
            .catch_unwind()
            .await
            .is_err()
    );
}
