use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use futures::FutureExt;

use crate::db::mem_impl::MemDatabase;
use crate::db::notifications::Notifications;
use crate::db::{
    BaseDatabaseTransaction, DatabaseError, DatabaseKeyPrefix, IDatabaseTransaction,
    IDatabaseTransactionOpsCore, IDatabaseTransactionOpsCoreTyped, IRawDatabase, IRawDatabaseExt,
    PrefixDatabaseTransaction, TestKey, TestVal,
};

#[tokio::test]
async fn no_previous_defaults_preserve_bytes_and_rollback() {
    let db = MemDatabase::new();
    let mut tx = db.begin_transaction().await;
    for (key, value) in [
        (vec![], vec![]),
        (vec![0, 255], vec![0, 255]),
        (vec![7; 65536], vec![8; 65536]),
    ] {
        tx.raw_insert_bytes_no_previous(&key, &value).await.unwrap();
        assert_eq!(tx.raw_get_bytes(&key).await.unwrap(), Some(value));
        tx.raw_remove_entry_no_previous(&key).await.unwrap();
        assert_eq!(tx.raw_get_bytes(&key).await.unwrap(), None);
        tx.raw_remove_entry_no_previous(&key).await.unwrap();
    }
    tx.raw_insert_bytes_no_previous(b"aborted", b"value")
        .await
        .unwrap();
    drop(tx);
    assert_eq!(
        db.begin_transaction()
            .await
            .raw_get_bytes(b"aborted")
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn typed_no_previous_explicitly_skips_corrupt_old_values() {
    let db = MemDatabase::new().into_database();
    let key = TestKey(1);
    for corrupt in [vec![], vec![255; 65536]] {
        let mut tx = db.begin_transaction().await;
        tx.raw_insert_bytes(&key.to_bytes(), &corrupt)
            .await
            .unwrap();
        assert!(
            AssertUnwindSafe(tx.insert_entry(&key, &TestVal(2)))
                .catch_unwind()
                .await
                .is_err()
        );
        // The legacy panic happens after the raw write. Use a fresh transaction
        // for each operation so this test also documents that distinction.
        drop(tx);
        let mut tx = db.begin_transaction().await;
        tx.raw_insert_bytes(&key.to_bytes(), &corrupt)
            .await
            .unwrap();
        tx.insert_entry_no_previous(&key, &TestVal(3)).await;
        assert_eq!(tx.get_value(&key).await, Some(TestVal(3)));
        tx.raw_insert_bytes(&key.to_bytes(), &corrupt)
            .await
            .unwrap();
        assert!(
            AssertUnwindSafe(tx.remove_entry(&key))
                .catch_unwind()
                .await
                .is_err()
        );
        tx.raw_insert_bytes(&key.to_bytes(), &corrupt)
            .await
            .unwrap();
        tx.remove_entry_no_previous(&key).await;
        assert_eq!(tx.get_value(&key).await, None);
    }
}

#[tokio::test]
async fn no_previous_wrappers_notify_only_after_commit() {
    let db = MemDatabase::new();
    let notifications = Arc::new(Notifications::new());
    let full_key = [7, 0, 255];
    for remove in [false, true] {
        for commit in [false, true] {
            let notified = notifications.register(full_key.as_slice());
            futures::pin_mut!(notified);
            assert!(futures::poll!(notified.as_mut()).is_pending());
            let base =
                BaseDatabaseTransaction::new(db.begin_transaction().await, notifications.clone());
            let mut prefixed = PrefixDatabaseTransaction {
                inner: base,
                prefix: vec![7],
                global_dbtx_access_token: None,
            };
            // Exercise both the Box and &mut forwarding implementations.
            let mut tx: Box<&mut dyn IDatabaseTransactionOpsCore> = Box::new(&mut prefixed);
            if remove {
                tx.raw_remove_entry_no_previous(&[0, 255]).await.unwrap();
            } else {
                tx.raw_insert_bytes_no_previous(&[0, 255], &[42])
                    .await
                    .unwrap();
            }
            assert!(futures::poll!(notified.as_mut()).is_pending());
            drop(tx);
            if commit {
                prefixed.commit_tx().await.unwrap();
                assert!(futures::poll!(notified.as_mut()).is_ready());
                assert!(matches!(
                    prefixed.raw_insert_bytes_no_previous(&[0], &[]).await,
                    Err(DatabaseError::TransactionConsumed)
                ));
                assert!(matches!(
                    prefixed.raw_remove_entry_no_previous(&[0]).await,
                    Err(DatabaseError::TransactionConsumed)
                ));
            } else {
                drop(prefixed);
                assert!(futures::poll!(notified.as_mut()).is_pending());
            }
        }
    }
    let mut tx = db.begin_transaction().await;
    assert_eq!(tx.raw_get_bytes(&[0, 255]).await.unwrap(), None);
    assert_eq!(tx.raw_get_bytes(&full_key).await.unwrap(), None);
}
