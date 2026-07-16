use std::time::{Duration, SystemTime};

use assert_matches::assert_matches;
use fedimint_client_module::oplog::{JsonStringed, OperationOutcome, UpdateStreamOrOutcome};
use fedimint_core::core::OperationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{
    Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped, IRawDatabaseExt,
};
use fedimint_core::module::registry::ModuleRegistry;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};

use crate::db::{ChronologicalOperationLogKey, OperationLogKey};
use crate::oplog::{OperationLog, OperationLogEntry};

#[test]
fn test_operation_log_entry_serde() {
    // Test with outcome = None
    let op_log = OperationLogEntry::new(
        "test".to_string(),
        JsonStringed(serde_json::to_value(()).unwrap()),
        None,
    );

    op_log.meta::<()>();
}

#[test]
fn test_operation_log_entry_serde_extra_meta() {
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    struct Meta {
        foo: String,
        extra_meta: serde_json::Value,
    }

    let meta = Meta {
        foo: "bar".to_string(),
        extra_meta: serde_json::to_value(()).unwrap(),
    };

    let op_log = OperationLogEntry::new(
        "test".to_string(),
        JsonStringed(serde_json::to_value(meta.clone()).unwrap()),
        Some(OperationOutcome {
            time: fedimint_core::time::now(),
            outcome: JsonStringed(serde_json::to_value("test_outcome").unwrap()),
        }),
    );

    assert_eq!(op_log.meta::<Meta>(), meta);
}

#[tokio::test]
async fn test_operation_log_update() {
    let op_id = OperationId([0x32; 32]);

    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let op_log = OperationLog::new(db.clone());

    let mut dbtx = db.begin_transaction().await;
    op_log
        .add_operation_log_entry_dbtx(&mut dbtx.to_ref_nc(), op_id, "foo", "bar")
        .await;
    dbtx.commit_tx().await;

    let op = op_log.get_operation(op_id).await.expect("op exists");
    assert_eq!(op.outcome::<String>(), None);

    OperationLog::set_operation_outcome(&db, op_id, &"baz")
        .await
        .unwrap();

    let op = op_log.get_operation(op_id).await.expect("op exists");
    assert_eq!(op.outcome::<String>(), Some("baz".to_string()));
    assert!(op.outcome_time().is_some(), "outcome_time should be set");

    let update_stream_or_outcome = OperationLog::outcome_or_updates::<String, _>(
        &db,
        op_id,
        &op,
        |_| true,
        futures::stream::empty,
    );

    assert_matches!(
        &update_stream_or_outcome,
        UpdateStreamOrOutcome::Outcome(s) if s == "baz"
    );

    let updates = update_stream_or_outcome
        .into_stream()
        .collect::<Vec<_>>()
        .await;
    assert_eq!(updates, vec!["baz"]);
}

#[tokio::test]
async fn test_operation_log_update_from_stream() {
    let op_id = OperationId([0x32; 32]);

    let db = MemDatabase::new().into_database();
    let op_log = OperationLog::new(db.clone());

    let mut dbtx = db.begin_transaction().await;
    op_log
        .add_operation_log_entry_dbtx(&mut dbtx.to_ref_nc(), op_id, "foo", "bar")
        .await;
    dbtx.commit_tx().await;

    let op = op_log.get_operation(op_id).await.expect("op exists");

    let updates = vec!["bar".to_owned(), "bob".to_owned(), "baz".to_owned()];
    let update_stream = OperationLog::outcome_or_updates::<String, _>(
        &db,
        op_id,
        &op,
        |_| true,
        || futures::stream::iter(updates.clone()),
    );

    let received_updates = update_stream.into_stream().collect::<Vec<_>>().await;
    assert_eq!(received_updates, updates);

    let op_updated = op_log.get_operation(op_id).await.expect("op exists");
    assert_eq!(op_updated.outcome::<String>(), Some("baz".to_string()));
    assert!(
        op_updated.outcome_time().is_some(),
        "outcome_time should be set after stream completion"
    );
}

/// A stream that ends on a NON-terminal update must not cache that update as
/// the operation's outcome: [`OperationLog::outcome_or_updates`]
/// short-circuits every later subscriber to a cached outcome, so caching a
/// non-terminal update would freeze the operation's observable state before
/// its actual end (e.g. an error-path early return in a module's stream
/// generator).
#[tokio::test]
async fn test_no_outcome_cached_for_non_terminal_stream_end() {
    let op_id = OperationId([0x32; 32]);

    let db = MemDatabase::new().into_database();
    let op_log = OperationLog::new(db.clone());

    let mut dbtx = db.begin_transaction().await;
    op_log
        .add_operation_log_entry_dbtx(&mut dbtx.to_ref_nc(), op_id, "foo", "bar")
        .await;
    dbtx.commit_tx().await;

    let op = op_log.get_operation(op_id).await.expect("op exists");

    // "pending" is not terminal, and the stream ends right after it.
    let update_stream = OperationLog::outcome_or_updates::<String, _>(
        &db,
        op_id,
        &op,
        |update| update == "final",
        || futures::stream::iter(vec!["created".to_owned(), "pending".to_owned()]),
    );
    let received = update_stream.into_stream().collect::<Vec<_>>().await;
    assert_eq!(received, vec!["created".to_owned(), "pending".to_owned()]);

    let op = op_log.get_operation(op_id).await.expect("op exists");
    assert_eq!(
        op.outcome::<String>(),
        None,
        "a non-terminal last update must not be cached as the outcome"
    );

    // A later subscription re-derives the full sequence and, once the stream
    // ends on a terminal update, caches it.
    let update_stream = OperationLog::outcome_or_updates::<String, _>(
        &db,
        op_id,
        &op,
        |update| update == "final",
        || {
            futures::stream::iter(vec![
                "created".to_owned(),
                "pending".to_owned(),
                "final".to_owned(),
            ])
        },
    );
    let _ = update_stream.into_stream().collect::<Vec<_>>().await;

    let op = op_log.get_operation(op_id).await.expect("op exists");
    assert_eq!(op.outcome::<String>(), Some("final".to_owned()));
}

/// A cached outcome that is NOT a terminal update — one frozen by a previous
/// version that cached whatever update a stream ended on — must not
/// short-circuit subscribers: it is discarded and the state is rebuilt from
/// the update stream, whose terminal end then overwrites the stale cache.
#[tokio::test]
async fn test_non_terminal_cached_outcome_falls_back_to_update_stream() {
    let op_id = OperationId([0x32; 32]);

    let db = MemDatabase::new().into_database();
    let op_log = OperationLog::new(db.clone());

    let mut dbtx = db.begin_transaction().await;
    op_log
        .add_operation_log_entry_dbtx(&mut dbtx.to_ref_nc(), op_id, "foo", "bar")
        .await;
    dbtx.commit_tx().await;

    // A previous version cached a non-terminal update as the outcome.
    OperationLog::set_operation_outcome(&db, op_id, &"pending")
        .await
        .unwrap();

    let op = op_log.get_operation(op_id).await.expect("op exists");
    let update_stream = OperationLog::outcome_or_updates::<String, _>(
        &db,
        op_id,
        &op,
        |update| update == "final",
        || futures::stream::iter(vec!["pending".to_owned(), "final".to_owned()]),
    );
    assert_matches!(
        &update_stream,
        UpdateStreamOrOutcome::UpdateStream(_),
        "a non-terminal cached outcome must not short-circuit subscribers"
    );
    let received = update_stream.into_stream().collect::<Vec<_>>().await;
    assert_eq!(received, vec!["pending".to_owned(), "final".to_owned()]);

    // The re-derived terminal has overwritten the stale cache, so the next
    // subscriber short-circuits to the true outcome.
    let op = op_log.get_operation(op_id).await.expect("op exists");
    assert_eq!(op.outcome::<String>(), Some("final".to_owned()));
    let update_stream = OperationLog::outcome_or_updates::<String, _>(
        &db,
        op_id,
        &op,
        |update| update == "final",
        futures::stream::empty,
    );
    assert_matches!(
        &update_stream,
        UpdateStreamOrOutcome::Outcome(o) if o == "final"
    );
}

/// A cached outcome that no longer deserializes into the expected update type
/// (e.g. written by an older version with a different update enum) must not
/// panic: it is discarded and the state is rebuilt from the update stream,
/// whose terminal end then overwrites the stale outcome.
#[tokio::test]
async fn test_undeserializable_outcome_falls_back_to_update_stream() {
    let op_id = OperationId([0x32; 32]);

    let db = MemDatabase::new().into_database();
    let op_log = OperationLog::new(db.clone());

    let mut dbtx = db.begin_transaction().await;
    op_log
        .add_operation_log_entry_dbtx(&mut dbtx.to_ref_nc(), op_id, "foo", "bar")
        .await;
    dbtx.commit_tx().await;

    // Cache an outcome of a shape the consumer type (String) cannot represent.
    OperationLog::set_operation_outcome(&db, op_id, &serde_json::json!({"old": "schema"}))
        .await
        .unwrap();

    let op = op_log.get_operation(op_id).await.expect("op exists");
    let update_stream = OperationLog::outcome_or_updates::<String, _>(
        &db,
        op_id,
        &op,
        |_| true,
        || futures::stream::iter(vec!["rebuilt".to_owned()]),
    );
    assert_matches!(&update_stream, UpdateStreamOrOutcome::UpdateStream(_));
    let received = update_stream.into_stream().collect::<Vec<_>>().await;
    assert_eq!(received, vec!["rebuilt".to_owned()]);

    let op = op_log.get_operation(op_id).await.expect("op exists");
    assert_eq!(
        op.outcome::<String>(),
        Some("rebuilt".to_owned()),
        "the stale outcome is overwritten by the re-derived terminal"
    );
}

#[tokio::test]
async fn test_pagination() {
    fn assert_page_entries(
        page: Vec<(ChronologicalOperationLogKey, OperationLogEntry)>,
        page_idx: u8,
    ) {
        for (entry_idx, (_key, entry)) in page.into_iter().enumerate() {
            let actual_meta = entry.meta::<u8>();
            let expected_meta = 97 - (page_idx * 10 + entry_idx as u8);

            assert_eq!(actual_meta, expected_meta);
        }
    }

    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let op_log = OperationLog::new(db.clone());

    for operation_idx in 0u8..98 {
        let mut dbtx = db.begin_transaction().await;
        op_log
            .add_operation_log_entry_dbtx(
                &mut dbtx.to_ref_nc(),
                OperationId([operation_idx; 32]),
                "foo",
                operation_idx,
            )
            .await;
        dbtx.commit_tx().await;
    }

    let mut previous_last_element = None;
    for page_idx in 0u8..9 {
        let page = op_log
            .paginate_operations_rev(10, previous_last_element)
            .await;
        assert_eq!(page.len(), 10);
        previous_last_element = Some(page[9].0);
        assert_page_entries(page, page_idx);
    }

    let page = op_log
        .paginate_operations_rev(10, previous_last_element)
        .await;
    assert_eq!(page.len(), 8);
    assert_page_entries(page, 9);
}

#[tokio::test]
async fn test_pagination_empty() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let op_log = OperationLog::new(db.clone());

    let page = op_log.paginate_operations_rev(10, None).await;
    assert!(page.is_empty());
}

#[tokio::test]
async fn test_pagination_multiple_operations_same_time() {
    async fn insert_oplog(dbtx: &mut DatabaseTransaction<'_>, idx: u8, time: u64) {
        let operation_id = OperationId([idx; 32]);
        // Some time in the 2010s
        let creation_time = SystemTime::UNIX_EPOCH
            + Duration::from_secs(60 * 60 * 24 * 365 * 40)
            + Duration::from_secs(time * 60 * 60 * 24);

        dbtx.insert_new_entry(
            &OperationLogKey { operation_id },
            &OperationLogEntry::new(
                "operation_type".to_string(),
                JsonStringed(serde_json::Value::Null),
                None,
            ),
        )
        .await;
        dbtx.insert_new_entry(
            &ChronologicalOperationLogKey {
                creation_time,
                operation_id,
            },
            &(),
        )
        .await;
    }

    async fn assert_pages(operation_log: &OperationLog, pages: Vec<Vec<u8>>) {
        let mut previous_last_element: Option<ChronologicalOperationLogKey> = None;
        for reference_page in pages {
            let page = operation_log
                .paginate_operations_rev(10, previous_last_element)
                .await;
            assert_eq!(page.len(), reference_page.len());
            assert_eq!(
                page.iter()
                    .map(|(operation_log_key, _)| operation_log_key.operation_id)
                    .collect::<Vec<_>>(),
                reference_page
                    .iter()
                    .map(|&x| OperationId([x; 32]))
                    .collect::<Vec<_>>()
            );
            previous_last_element = page.last().map(|(key, _)| key).copied();
        }
    }

    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let op_log = OperationLog::new(db.clone());

    let mut dbtx = db.begin_transaction().await;
    for operation_idx in 0u8..10 {
        insert_oplog(&mut dbtx.to_ref_nc(), operation_idx, 1).await;
    }
    dbtx.commit_tx().await;
    assert_pages(&op_log, vec![vec![9, 8, 7, 6, 5, 4, 3, 2, 1, 0], vec![]]).await;

    let mut dbtx = db.begin_transaction().await;
    for operation_idx in 10u8..16 {
        insert_oplog(&mut dbtx.to_ref_nc(), operation_idx, 2).await;
    }
    for operation_idx in 16u8..22 {
        insert_oplog(&mut dbtx.to_ref_nc(), operation_idx, 3).await;
    }
    dbtx.commit_tx().await;
    assert_pages(
        &op_log,
        vec![
            vec![21, 20, 19, 18, 17, 16, 15, 14, 13, 12],
            vec![11, 10, 9, 8, 7, 6, 5, 4, 3, 2],
            vec![1, 0],
            vec![],
        ],
    )
    .await;

    let mut dbtx = db.begin_transaction().await;
    for operation_idx in 22u8..31 {
        // 9 times one operation every 10 days
        insert_oplog(
            &mut dbtx.to_ref_nc(),
            operation_idx,
            10 * u64::from(operation_idx),
        )
        .await;
    }
    dbtx.commit_tx().await;
    assert_pages(
        &op_log,
        vec![
            vec![30, 29, 28, 27, 26, 25, 24, 23, 22, 21],
            vec![20, 19, 18, 17, 16, 15, 14, 13, 12, 11],
            vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
            vec![0],
            vec![],
        ],
    )
    .await;
}

#[tokio::test]
async fn test_pagination_empty_then_not() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let op_log = OperationLog::new(db.clone());

    let page = op_log.paginate_operations_rev(10, None).await;
    assert!(page.is_empty());

    let mut dbtx = db.begin_transaction().await;
    op_log
        .add_operation_log_entry_dbtx(&mut dbtx.to_ref_nc(), OperationId([0; 32]), "foo", "bar")
        .await;
    dbtx.commit_tx().await;

    let page = op_log.paginate_operations_rev(10, None).await;
    assert_eq!(page.len(), 1);
}

#[tokio::test]
async fn test_pagination_after_historical_insert() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let op_log = OperationLog::new(db.clone());

    let recent_operation_id = OperationId([1; 32]);
    let recent_creation_time = fedimint_core::time::now() - Duration::from_secs(60);
    let mut dbtx = db.begin_transaction().await;
    op_log
        .add_operation_log_entry_dbtx_with_creation_time(
            &mut dbtx.to_ref_nc(),
            recent_operation_id,
            "foo",
            1u8,
            recent_creation_time,
        )
        .await;
    dbtx.commit_tx().await;

    let page = op_log.paginate_operations_rev(10, None).await;
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].0.operation_id, recent_operation_id);

    let historical_operation_id = OperationId([0; 32]);
    let historical_creation_time = recent_creation_time - Duration::from_secs(60);
    let mut dbtx = db.begin_transaction().await;
    op_log
        .add_operation_log_entry_dbtx_with_creation_time(
            &mut dbtx.to_ref_nc(),
            historical_operation_id,
            "foo",
            0u8,
            historical_creation_time,
        )
        .await;
    dbtx.commit_tx().await;

    let page = op_log.paginate_operations_rev(10, None).await;
    assert_eq!(
        page.iter()
            .map(|(key, _)| key.operation_id)
            .collect::<Vec<_>>(),
        vec![recent_operation_id, historical_operation_id]
    );
}
