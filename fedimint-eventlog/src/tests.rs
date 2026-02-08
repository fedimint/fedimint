use std::sync::Arc;
use std::sync::atomic::AtomicU8;

use anyhow::bail;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{
    IRawDatabaseExt as _, IReadDatabaseTransactionOpsTyped as _,
    IWriteDatabaseTransactionOpsTyped as _, NonCommittable, WriteDatabaseTransaction,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::TaskGroup;
use fedimint_core::{apply, async_trait_maybe_send, impl_db_record};
use futures::StreamExt as _;
use tokio::sync::{broadcast, watch};
use tokio::try_join;
use tracing::info;

use super::{
    DBTransactionEventLogExt as _, EventKind, EventLogEntry, EventLogId, EventLogTrimableId,
    EventLogTrimableIdPrefixAll, TRIMABLE_EVENTLOG_MIN_ID_AGE, TRIMABLE_EVENTLOG_MIN_TS_AGE,
    handle_events, run_event_log_ordering_task, trim_trimable_log,
};
use crate::EventLogNonTrimableTracker;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
pub struct TestEventLogIdKey;

impl_db_record!(
    key = TestEventLogIdKey,
    value = EventLogId,
    db_prefix = 0x00,
);

struct TestEventLogTracker;

#[apply(async_trait_maybe_send!)]
impl EventLogNonTrimableTracker for TestEventLogTracker {
    // Store position in the event log
    async fn store(
        &mut self,
        dbtx: &mut WriteDatabaseTransaction<'_, NonCommittable>,
        pos: EventLogId,
    ) -> anyhow::Result<()> {
        dbtx.insert_entry(&TestEventLogIdKey, &pos).await;
        Ok(())
    }

    /// Load the last previous stored position (or None if never stored)
    async fn load(
        &mut self,
        dbtx: &mut WriteDatabaseTransaction<'_, NonCommittable>,
    ) -> anyhow::Result<Option<EventLogId>> {
        Ok(dbtx.get_value(&TestEventLogIdKey).await)
    }
}

#[test_log::test(tokio::test)]
async fn sanity_handle_events() {
    let db = MemDatabase::new().into_database();
    let tg = TaskGroup::new();

    let (log_event_added_tx, log_event_added_rx) = watch::channel(());
    let (log_ordering_wakeup_tx, log_ordering_wakeup_rx) = watch::channel(());
    let (log_event_added_transient_tx, _log_event_added_transient_rx) = broadcast::channel(1024);

    tg.spawn_cancellable(
        "event log ordering task",
        run_event_log_ordering_task(
            db.clone(),
            log_ordering_wakeup_rx,
            log_event_added_tx,
            log_event_added_transient_tx,
        ),
    );

    let counter = Arc::new(AtomicU8::new(0));

    let _ = try_join!(
        handle_events(
            db.clone(),
            Box::new(TestEventLogTracker),
            log_event_added_rx,
            move |_dbtx, event| {
                let counter = counter.clone();
                Box::pin(async move {
                    info!("{event:?}");

                    assert_eq!(
                        event.kind,
                        EventKind::from(format!(
                            "{}",
                            counter.load(std::sync::atomic::Ordering::Relaxed)
                        ))
                    );

                    if counter.load(std::sync::atomic::Ordering::Relaxed) == 4 {
                        bail!("Time to wrap up");
                    }
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(())
                })
            },
        ),
        async {
            for i in 0..=4 {
                let mut dbtx = db.begin_write_transaction().await;
                dbtx.log_event_raw(
                    log_ordering_wakeup_tx.clone(),
                    EventKind::from(format!("{i}")),
                    None,
                    None,
                    vec![],
                    crate::EventPersistence::Persistent,
                )
                .await;

                dbtx.commit_tx().await;
            }

            Ok(())
        }
    );
}

#[test_log::test(tokio::test)]
async fn test_trim_trimable_log() {
    let db = MemDatabase::new().into_database();

    // Create test data: 2 * TRIMABLE_EVENTLOG_MIN_ID_AGE entries
    let num_entries = (2 * TRIMABLE_EVENTLOG_MIN_ID_AGE) as usize;
    let base_timestamp = 1_000_000_000_000_000u64; // Some base time in microseconds
    let timestamp_increment = 60 * 1_000_000u64; // 1 minute in microseconds

    // Populate the trimable log with test entries
    {
        let mut dbtx = db.begin_write_transaction().await;

        for i in 0..num_entries {
            let id = EventLogTrimableId::from(i as u64);
            let entry = EventLogEntry {
                kind: EventKind::from(format!("test_event_{i}")),
                module: None,
                ts_usecs: base_timestamp + (i as u64 * timestamp_increment),
                payload: format!("test_payload_{i}").into_bytes(),
            };

            dbtx.insert_entry(&id, &entry).await;
        }

        dbtx.commit_tx().await;
    }

    // Verify all entries were inserted
    {
        let mut dbtx = db.begin_read_transaction().await;
        let count = dbtx
            .find_by_prefix(&EventLogTrimableIdPrefixAll)
            .await
            .count()
            .await;
        assert_eq!(count, num_entries);
    }

    // Calculate current time that would make entries old enough to be trimmed
    // We want the first TRIMABLE_EVENTLOG_MIN_ID_AGE entries to be old enough
    let entries_to_trim = TRIMABLE_EVENTLOG_MIN_ID_AGE as usize;
    let last_old_entry_timestamp =
        base_timestamp + ((entries_to_trim - 1) as u64 * timestamp_increment);
    let current_time = last_old_entry_timestamp + TRIMABLE_EVENTLOG_MIN_TS_AGE + 1;

    // Call trim_trimable_log
    trim_trimable_log(&db, current_time).await;

    // Verify the expected number of entries were deleted
    {
        let mut dbtx = db.begin_read_transaction().await;
        let remaining_count = dbtx
            .find_by_prefix(&EventLogTrimableIdPrefixAll)
            .await
            .count()
            .await;

        // Should have deleted exactly TRIMABLE_EVENTLOG_MIN_ID_AGE entries
        let expected_remaining = num_entries - entries_to_trim;
        assert_eq!(remaining_count, expected_remaining);

        // Verify the remaining entries are the newer ones
        let remaining_ids: Vec<_> = dbtx
            .find_by_prefix(&EventLogTrimableIdPrefixAll)
            .await
            .map(|(id, _)| id.0.0)
            .collect()
            .await;

        // The remaining IDs should start from TRIMABLE_EVENTLOG_MIN_ID_AGE
        let expected_start_id = TRIMABLE_EVENTLOG_MIN_ID_AGE;
        assert_eq!(remaining_ids[0], expected_start_id);
        assert_eq!(remaining_ids.len(), expected_remaining);
    }
}
