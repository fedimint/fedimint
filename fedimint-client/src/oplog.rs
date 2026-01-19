use std::collections::HashSet;
use std::fmt::Debug;
use std::ops::Range;
use std::time::Duration;

use fedimint_client_module::oplog::{
    IOperationLog, JsonStringed, OperationLogEntry, OperationOutcome, UpdateStreamOrOutcome,
};
use fedimint_core::core::OperationId;
use fedimint_core::db::{
    Database, IReadDatabaseTransactionOpsTyped, IWriteDatabaseTransactionOpsTyped as _,
    WriteDatabaseTransaction,
};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::time::now;
use fedimint_core::util::BoxStream;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_CLIENT;
use futures::StreamExt as _;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::OnceCell;
use tracing::{error, instrument, warn};

use crate::db::{ChronologicalOperationLogKey, OperationLogKey};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub struct OperationLog {
    db: Database,
    oldest_entry: tokio::sync::OnceCell<ChronologicalOperationLogKey>,
}

impl OperationLog {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            oldest_entry: OnceCell::new(),
        }
    }

    /// Will return the oldest operation log key in the database and cache the
    /// result. If no entry exists yet the DB will be queried on each call till
    /// an entry is present.
    async fn get_oldest_operation_log_key(&self) -> Option<ChronologicalOperationLogKey> {
        let mut dbtx = self.db.begin_read_transaction().await;
        self.oldest_entry
            .get_or_try_init(move || async move {
                dbtx.find_by_prefix(&crate::db::ChronologicalOperationLogKeyPrefix)
                    .await
                    .map(|(key, ())| key)
                    .next()
                    .await
                    .ok_or(())
            })
            .await
            .ok()
            .copied()
    }

    pub async fn add_operation_log_entry_dbtx(
        &self,
        dbtx: &mut WriteDatabaseTransaction<'_>,
        operation_id: OperationId,
        operation_type: &str,
        operation_meta: impl serde::Serialize,
    ) {
        dbtx.insert_new_entry(
            &OperationLogKey { operation_id },
            &OperationLogEntry::new(
                operation_type.to_string(),
                JsonStringed(
                    serde_json::to_value(operation_meta)
                        .expect("Can only fail if meta is not serializable"),
                ),
                None,
            ),
        )
        .await;
        dbtx.insert_new_entry(
            &ChronologicalOperationLogKey {
                creation_time: now(),
                operation_id,
            },
            &(),
        )
        .await;
    }

    #[deprecated(since = "0.6.0", note = "Use `paginate_operations_rev` instead")]
    pub async fn list_operations(
        &self,
        limit: usize,
        last_seen: Option<ChronologicalOperationLogKey>,
    ) -> Vec<(ChronologicalOperationLogKey, OperationLogEntry)> {
        self.paginate_operations_rev(limit, last_seen).await
    }

    /// Returns the last `limit` operations. To fetch the next page, pass the
    /// last operation's [`ChronologicalOperationLogKey`] as `start_after`.
    pub async fn paginate_operations_rev(
        &self,
        limit: usize,
        last_seen: Option<ChronologicalOperationLogKey>,
    ) -> Vec<(ChronologicalOperationLogKey, OperationLogEntry)> {
        const EPOCH_DURATION: Duration = Duration::from_secs(60 * 60 * 24 * 7);

        let start_after_key = last_seen.unwrap_or_else(|| ChronologicalOperationLogKey {
            // We don't expect any operations from the future to exist, since SystemTime isn't
            // monotone and CI can be overloaded at times we add a small buffer to avoid flakiness
            // in tests.
            creation_time: now() + Duration::from_secs(30),
            operation_id: OperationId([0; 32]),
        });

        let Some(oldest_entry_key) = self.get_oldest_operation_log_key().await else {
            return vec![];
        };

        let mut dbtx = self.db.begin_read_transaction().await;
        let mut operation_log_keys = Vec::with_capacity(32);

        // Find all the operation log keys in the requested window. Since we decided to
        // not introduce a find_by_range_rev function we have to jump through some
        // hoops, see also the comments in rev_epoch_ranges.
        // TODO: Implement using find_by_range_rev if ever introduced
        'outer: for key_range_rev in
            rev_epoch_ranges(start_after_key, oldest_entry_key, EPOCH_DURATION)
        {
            let epoch_operation_log_keys_rev = dbtx
                .find_by_range(key_range_rev)
                .await
                .map(|(key, ())| key)
                .collect::<Vec<_>>()
                .await;

            for operation_log_key in epoch_operation_log_keys_rev.into_iter().rev() {
                operation_log_keys.push(operation_log_key);
                if operation_log_keys.len() >= limit {
                    break 'outer;
                }
            }
        }

        debug_assert!(
            operation_log_keys.iter().collect::<HashSet<_>>().len() == operation_log_keys.len(),
            "Operation log keys returned are not unique"
        );

        let mut operation_log_entries = Vec::with_capacity(operation_log_keys.len());
        for operation_log_key in operation_log_keys {
            let operation_log_entry = dbtx
                .get_value(&OperationLogKey {
                    operation_id: operation_log_key.operation_id,
                })
                .await
                .expect("Inconsistent DB");
            operation_log_entries.push((operation_log_key, operation_log_entry));
        }

        operation_log_entries
    }

    pub async fn get_operation(&self, operation_id: OperationId) -> Option<OperationLogEntry> {
        Self::get_operation_dbtx(&mut self.db.begin_read_transaction().await, operation_id).await
    }

    pub async fn get_operation_dbtx<'a>(
        dbtx: &mut (impl IReadDatabaseTransactionOpsTyped<'a> + MaybeSend),
        operation_id: OperationId,
    ) -> Option<OperationLogEntry> {
        dbtx.get_value(&OperationLogKey { operation_id }).await
    }

    /// Sets the outcome of an operation
    #[instrument(target = LOG_CLIENT, skip(db), level = "debug")]
    pub async fn set_operation_outcome(
        db: &Database,
        operation_id: OperationId,
        outcome: &(impl Serialize + Debug),
    ) -> anyhow::Result<()> {
        let outcome_json =
            JsonStringed(serde_json::to_value(outcome).expect("Outcome is not serializable"));

        let mut dbtx = db.begin_write_transaction().await;
        let mut operation = Self::get_operation_dbtx(&mut dbtx.to_ref_nc(), operation_id)
            .await
            .expect("Operation exists");
        operation.set_outcome(OperationOutcome {
            time: fedimint_core::time::now(),
            outcome: outcome_json,
        });
        dbtx.insert_entry(&OperationLogKey { operation_id }, &operation)
            .await;
        dbtx.commit_tx_result().await?;

        Ok(())
    }

    /// Returns an a [`UpdateStreamOrOutcome`] enum that can be converted into
    /// an update stream for easier handling using
    /// [`UpdateStreamOrOutcome::into_stream`] but can also be matched over to
    /// shortcut the handling of final outcomes.
    pub fn outcome_or_updates<U, S>(
        db: &Database,
        operation_id: OperationId,
        operation_log_entry: OperationLogEntry,
        stream_gen: impl FnOnce() -> S,
    ) -> UpdateStreamOrOutcome<U>
    where
        U: Clone + Serialize + DeserializeOwned + Debug + MaybeSend + MaybeSync + 'static,
        S: futures::Stream<Item = U> + MaybeSend + 'static,
    {
        match operation_log_entry.outcome::<U>() {
            Some(outcome) => UpdateStreamOrOutcome::Outcome(outcome),
            None => UpdateStreamOrOutcome::UpdateStream(caching_operation_update_stream(
                db.clone(),
                operation_id,
                stream_gen(),
            )),
        }
    }

    /// Tries to set the outcome of an operation, but only logs an error if it
    /// fails and does not return it. Since the outcome can always be recomputed
    /// from an update stream, failing to save it isn't a problem in cases where
    /// we do this merely for caching.
    pub async fn optimistically_set_operation_outcome(
        db: &Database,
        operation_id: OperationId,
        outcome: &(impl Serialize + Debug),
    ) {
        if let Err(e) = Self::set_operation_outcome(db, operation_id, outcome).await {
            warn!(
                target: LOG_CLIENT,
                "Error setting operation outcome: {e}"
            );
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl IOperationLog for OperationLog {
    async fn get_operation(&self, operation_id: OperationId) -> Option<OperationLogEntry> {
        OperationLog::get_operation(self, operation_id).await
    }

    async fn get_operation_dbtx(
        &self,
        dbtx: &mut WriteDatabaseTransaction<'_>,
        operation_id: OperationId,
    ) -> Option<OperationLogEntry> {
        OperationLog::get_operation_dbtx(dbtx, operation_id).await
    }

    async fn add_operation_log_entry_dbtx(
        &self,
        dbtx: &mut WriteDatabaseTransaction<'_>,
        operation_id: OperationId,
        operation_type: &str,
        operation_meta: serde_json::Value,
    ) {
        OperationLog::add_operation_log_entry_dbtx(
            self,
            dbtx,
            operation_id,
            operation_type,
            operation_meta,
        )
        .await
    }

    fn outcome_or_updates(
        &self,
        db: &Database,
        operation_id: OperationId,
        operation: OperationLogEntry,
        stream_gen: Box<dyn FnOnce() -> BoxStream<'static, serde_json::Value>>,
    ) -> UpdateStreamOrOutcome<serde_json::Value> {
        match OperationLog::outcome_or_updates(db, operation_id, operation, stream_gen) {
            UpdateStreamOrOutcome::UpdateStream(pin) => UpdateStreamOrOutcome::UpdateStream(pin),
            UpdateStreamOrOutcome::Outcome(o) => {
                UpdateStreamOrOutcome::Outcome(serde_json::from_value(o).expect("Can't fail"))
            }
        }
    }
}
/// Returns an iterator over the ranges of operation log keys, starting from the
/// most recent range and going backwards in time till slightly later than
/// `last_entry`.
///
/// Simplifying keys to integers and assuming a `start_after` of 100, a
/// `last_entry` of 55 and an `epoch_duration` of 10 the ranges would be:
/// ```text
/// [90..100, 80..90, 70..80, 60..70, 50..60]
/// ```
fn rev_epoch_ranges(
    start_after: ChronologicalOperationLogKey,
    last_entry: ChronologicalOperationLogKey,
    epoch_duration: Duration,
) -> impl Iterator<Item = Range<ChronologicalOperationLogKey>> {
    // We want to fetch all operations that were created before `start_after`, going
    // backwards in time. This means "start" generally means a later time than
    // "end". Only when creating a rust Range we have to swap the terminology (see
    // comment there).
    (0..)
        .map(move |epoch| start_after.creation_time - epoch * epoch_duration)
        // We want to get all operation log keys in the range [last_key, start_after). So as
        // long as the start time is greater than the last key's creation time, we have to
        // keep going.
        .take_while(move |&start_time| start_time >= last_entry.creation_time)
        .map(move |start_time| {
            let end_time = start_time - epoch_duration;

            // In the edge case that there were two events logged at exactly the same time
            // we need to specify the correct operation_id for the first key. Otherwise, we
            // could miss entries.
            let start_key = if start_time == start_after.creation_time {
                start_after
            } else {
                ChronologicalOperationLogKey {
                    creation_time: start_time,
                    operation_id: OperationId([0; 32]),
                }
            };

            // We could also special-case the last key here, but it's not necessary, making
            // it last_key if end_time < last_key.creation_time. We know there are no
            // entries beyond last_key though, so the range query will be equivalent either
            // way.
            let end_key = ChronologicalOperationLogKey {
                creation_time: end_time,
                operation_id: OperationId([0; 32]),
            };

            // We want to go backwards using a forward range query. This means we have to
            // swap the start and end keys and then reverse the vector returned by the
            // query.
            Range {
                start: end_key,
                end: start_key,
            }
        })
}

/// Wraps an operation update stream such that the last update before it closes
/// is tried to be written to the operation log entry as its outcome.
pub fn caching_operation_update_stream<'a, U, S>(
    db: Database,
    operation_id: OperationId,
    stream: S,
) -> BoxStream<'a, U>
where
    U: Clone + Serialize + Debug + MaybeSend + MaybeSync + 'static,
    S: futures::Stream<Item = U> + MaybeSend + 'a,
{
    let mut stream = Box::pin(stream);
    Box::pin(async_stream::stream! {
        let mut last_update = None;
        while let Some(update) = stream.next().await {
            yield update.clone();
            last_update = Some(update);
        }

        let Some(last_update) = last_update else {
            error!(
                target: LOG_CLIENT,
                "Stream ended without any updates, this should not happen!"
            );
            return;
        };

        OperationLog::optimistically_set_operation_outcome(&db, operation_id, &last_update).await;
    })
}
