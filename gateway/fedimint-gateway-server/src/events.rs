use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use fedimint_client::ClientHandle;
use fedimint_eventlog::{
    DBTransactionEventLogReadExt, Event, EventKind, EventLogId, PersistedLogEntry,
};
use fedimint_gwv2_client::events::{
    CompleteLightningPaymentSucceeded, IncomingPaymentFailed, IncomingPaymentStarted,
    IncomingPaymentSucceeded, OutgoingPaymentFailed, OutgoingPaymentStarted,
    OutgoingPaymentSucceeded,
};
use fedimint_mint_client::event::{OOBNotesReissued, OOBNotesSpent};
use fedimint_wallet_client::events::{DepositConfirmed, WithdrawRequest};

pub const ALL_GATEWAY_EVENTS: [EventKind; 11] = [
    OutgoingPaymentStarted::KIND,
    OutgoingPaymentSucceeded::KIND,
    OutgoingPaymentFailed::KIND,
    IncomingPaymentStarted::KIND,
    IncomingPaymentSucceeded::KIND,
    IncomingPaymentFailed::KIND,
    CompleteLightningPaymentSucceeded::KIND,
    OOBNotesSpent::KIND,
    OOBNotesReissued::KIND,
    WithdrawRequest::KIND,
    DepositConfirmed::KIND,
];

/// Searches through the event log for all events that occurred within the
/// specified time bounds.
///
/// Because it is inefficient to search the log backwards, instead this function
/// traverses the log forwards, but in batches.
/// All events are appended to an array until the cutoff event where the
/// timestamp is greater than the start timestamp or the end of the log is hit.
pub async fn get_events_for_duration(
    client: &Arc<ClientHandle>,
    start: SystemTime,
    end: SystemTime,
) -> Vec<PersistedLogEntry> {
    const BATCH_SIZE: u64 = 10_000;

    let start_micros = start
        .duration_since(UNIX_EPOCH)
        .expect("before unix epoch")
        .as_micros() as u64;

    let end_micros = end
        .duration_since(UNIX_EPOCH)
        .expect("before unix epoch")
        .as_micros() as u64;

    let batch_end = {
        let mut dbtx = client.db().begin_read_transaction().await;
        dbtx.get_next_event_log_id().await
    };

    let mut batch_start = batch_end.saturating_sub(BATCH_SIZE);

    // Find the "rough start" in the log by reading the log backwards in batches.
    // Once an event with a timestamp before our start time is found, then we start
    // traversing forward to find events that fall within our time bound.
    while batch_start != EventLogId::LOG_START {
        let batch = client.get_event_log(Some(batch_start), BATCH_SIZE).await;

        match batch.first() {
            Some(first_event) => {
                if first_event.as_raw().ts_usecs < start_micros {
                    // Found the "rough start" where we can read forward
                    break;
                }
            }
            None => {
                return vec![];
            }
        }

        batch_start = batch_start.saturating_sub(BATCH_SIZE);
    }

    let mut all_events = Vec::new();
    loop {
        let batch = client.get_event_log(Some(batch_start), BATCH_SIZE).await;

        if batch.is_empty() {
            return all_events;
        }

        for event in batch {
            if event.as_raw().ts_usecs < start_micros {
                continue;
            }

            if event.as_raw().ts_usecs >= end_micros {
                return all_events;
            }

            all_events.push(event);
        }

        batch_start = batch_start.saturating_add(BATCH_SIZE);
    }
}
