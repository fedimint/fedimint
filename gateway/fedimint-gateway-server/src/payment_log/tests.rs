use std::cell::RefCell;
use std::future::ready;

use fedimint_eventlog::EventLogId;

use super::collect_backwards;

/// Pages through a log whose entries are their own ids, keeping the ids
/// accepted by `keep`, and records every `(start, count)` fetched.
async fn collect(
    log: &[u64],
    end_position: u64,
    limit: usize,
    batch_size: u64,
    keep: impl Fn(&u64) -> bool,
) -> (Vec<u64>, Vec<(u64, u64)>) {
    let fetches = RefCell::new(Vec::new());

    let entries = collect_backwards(
        EventLogId::LOG_START.saturating_add(end_position),
        limit,
        batch_size,
        |start, count| {
            let start = u64::from(start);
            fetches.borrow_mut().push((start, count));

            ready(
                log.iter()
                    .copied()
                    .filter(|id| (start..start + count).contains(id))
                    .collect(),
            )
        },
        keep,
    )
    .await;

    (entries, fetches.into_inner())
}

#[tokio::test]
async fn the_end_position_is_included() {
    let log: Vec<u64> = (0..30).collect();

    let (entries, fetches) = collect(&log, 25, 3, 10, |_| true).await;

    assert_eq!(entries, vec![25, 24, 23]);
    assert_eq!(fetches, vec![(16, 10)]);
}

#[tokio::test]
async fn consecutive_pages_neither_skip_nor_repeat_entries() {
    let log: Vec<u64> = (0..30).collect();

    // Like the gateway UI, ask for each next page just below the last entry
    let mut end_position = 29;
    let mut seen: Vec<u64> = Vec::new();

    loop {
        let (page, _) = collect(&log, end_position, 4, 10, |_| true).await;
        seen.extend(&page);

        match page.last() {
            Some(0) | None => break,
            Some(last) => end_position = last - 1,
        }
    }

    assert_eq!(seen, (0..30).rev().collect::<Vec<_>>());
}

#[tokio::test]
async fn the_batch_at_the_start_of_the_log_is_read() {
    let log: Vec<u64> = (0..30).collect();

    // Only a few entries match, so every batch down to the start of the log
    // has to be read to fill the page.
    let (entries, fetches) = collect(&log, 25, 10, 10, |id| id % 7 == 0).await;

    assert_eq!(entries, vec![21, 14, 7, 0]);
    assert_eq!(fetches, vec![(16, 10), (6, 10), (0, 6)]);
}

#[tokio::test]
async fn reading_stops_once_the_page_is_full() {
    let log: Vec<u64> = (0..30).collect();

    let (entries, fetches) = collect(&log, 29, 12, 10, |_| true).await;

    assert_eq!(entries, (18..30).rev().collect::<Vec<_>>());
    assert_eq!(fetches, vec![(20, 10), (10, 10)]);
}
