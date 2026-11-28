use std::future::Future;

use fedimint_eventlog::EventLogId;

/// Collects up to `limit` entries accepted by `keep`, newest first, from the
/// event log ids at or below `end_position`.
///
/// `fetch(start, count)` must return the entries with ids in
/// `start..start + count`, oldest first. It is called with consecutive,
/// non-overlapping batches of at most `batch_size` ids, going backwards from
/// `end_position`, until enough entries were collected or the batch starting
/// at the beginning of the log was read.
pub(crate) async fn collect_backwards<T, Fut>(
    end_position: EventLogId,
    limit: usize,
    batch_size: u64,
    mut fetch: impl FnMut(EventLogId, u64) -> Fut,
    keep: impl Fn(&T) -> bool,
) -> Vec<T>
where
    Fut: Future<Output = Vec<T>>,
{
    let mut entries = Vec::new();

    // Exclusive end of the next batch, so that `end_position` itself is read
    let mut batch_end = end_position.saturating_add(1);

    while entries.len() < limit {
        let batch_start = batch_end.saturating_sub(batch_size);
        let count = u64::from(batch_end) - u64::from(batch_start);

        let batch = fetch(batch_start, count).await;
        entries.extend(batch.into_iter().rev().filter(|entry| keep(entry)));

        if batch_start == EventLogId::LOG_START {
            break;
        }

        batch_end = batch_start;
    }

    entries.truncate(limit);

    entries
}

#[cfg(test)]
mod tests;
