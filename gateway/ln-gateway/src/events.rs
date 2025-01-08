use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use fedimint_client::ClientHandle;
use fedimint_core::core::ModuleKind;
use fedimint_core::time::now;
use fedimint_core::Amount;
use fedimint_eventlog::{
    DBTransactionEventLogExt, Event, EventKind, EventLogId, PersistedLogEntry,
};
use fedimint_mint_client::event::{OOBNotesReissued, OOBNotesSpent};
use fedimint_wallet_client::events::{DepositConfirmed, WithdrawRequest};
use itertools::Itertools;

use crate::gateway_module_v2::events::{
    CompleteLightningPaymentSucceeded, IncomingPaymentFailed, IncomingPaymentStarted,
    IncomingPaymentSucceeded, OutgoingPaymentFailed, OutgoingPaymentStarted,
    OutgoingPaymentSucceeded,
};
use crate::rpc::{PaymentStats, PaymentSummaryResponse};

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

/// Searches through the event log for all events that occurred within the last
/// 24 hours. Because it is inefficient to search the log backwards, instead
/// this function traverses the log forwards, but in batches of 10000 events.
/// All events are appended to an array until the cutoff event where the
/// timestamp is greater than a day old is found.
pub async fn get_last_day_events(client: &Arc<ClientHandle>) -> Vec<PersistedLogEntry> {
    // Start at the end of the log and find the first event where the timestamp <
    // `one_day_ago`
    const BATCH_SIZE: u64 = 10_000;
    let end_position = {
        let mut dbtx = client.db().begin_transaction_nc().await;
        dbtx.get_next_event_log_id().await
    };

    let mut start_position = end_position.saturating_sub(BATCH_SIZE);
    let mut all_events = Vec::new();
    let mut batch = client.get_event_log(Some(start_position), BATCH_SIZE).await;
    let mut index = get_earliest_index(&batch);
    let log_start = EventLogId::new(0);
    // An index of 0 indicates that all events were within the last day and we
    // should re-query for more events.
    while index == 0 {
        all_events.append(&mut batch);
        // Compute the start position for the next batch query
        start_position = start_position.saturating_sub(BATCH_SIZE);

        if start_position == log_start {
            break;
        }
        batch = client.get_event_log(Some(start_position), BATCH_SIZE).await;
        index = get_earliest_index(&batch);
    }

    let partial_events = &batch[index..];
    all_events.append(&mut partial_events.to_vec());
    all_events
}

/// Binary searches the `PersistedLogEntry` slice for a timestamp
/// that is older than one day old. If all events are within the last day
/// then the index of 0 is returned.
fn get_earliest_index(batch: &[PersistedLogEntry]) -> usize {
    let one_day_ago = now()
        .checked_sub(Duration::from_secs(60 * 60 * 24))
        .expect("outside valid SystemTime bounds");
    let timestamps = batch.iter().map(|e| e.timestamp).collect::<Vec<_>>();
    let one_day_ago_micros = one_day_ago
        .duration_since(UNIX_EPOCH)
        .expect("before unix epoch")
        .as_micros() as u64;
    let index = timestamps.binary_search(&one_day_ago_micros);
    match index {
        Err(index) | Ok(index) => index,
    }
}

/// Filters the given `PersistedLogEntry` slice by the `EventKind` and
/// `ModuleKind`.
pub(crate) fn filter_events(
    all_events: &[PersistedLogEntry],
    event_kind: EventKind,
    module_kind: ModuleKind,
) -> Vec<&PersistedLogEntry> {
    let events = all_events
        .iter()
        .filter(|e| {
            if let Some((m, _)) = &e.module {
                e.event_kind == event_kind && *m == module_kind
            } else {
                false
            }
        })
        .collect::<Vec<_>>();
    drop(event_kind);
    drop(module_kind);
    events
}

/// This function computes a "nested loop join" by first computing the cross
/// product of the start event vector and the success/failure event vectors. The
/// resulting cartesian product is then filtered according to the join predicate
/// supplied in the parameters.
///
/// This function is intended for small data sets. If the data set relations
/// grow, this function should implement a different join algorithm or be moved
/// out of the gateway.
pub(crate) fn join_events<Start, Success, Failure>(
    start_events: &Vec<&PersistedLogEntry>,
    success_events: &Vec<&PersistedLogEntry>,
    failure_events: &Vec<&PersistedLogEntry>,
    success_join_predicate: fn(Start, Success, u64) -> Option<(u64, Amount)>,
    failure_join_predicate: fn(Start, Failure, u64) -> Option<u64>,
) -> (Vec<(u64, Amount)>, Vec<u64>)
where
    Start: Event,
    Success: Event,
    Failure: Event,
{
    let cross_product = start_events
        .iter()
        .cartesian_product(success_events)
        .collect::<Vec<_>>();
    let success_stats = cross_product
        .into_iter()
        .filter_map(|(start, success)| {
            if let Some(latency) = success.timestamp.checked_sub(start.timestamp) {
                let start_event: Start =
                    serde_json::from_value(start.value.clone()).expect("could not parse JSON");
                let success_event: Success =
                    serde_json::from_value(success.value.clone()).expect("could not parse JSON");
                success_join_predicate(start_event, success_event, latency)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let cross_product = start_events
        .iter()
        .cartesian_product(failure_events)
        .collect::<Vec<_>>();
    let failure_stats = cross_product
        .into_iter()
        .filter_map(|(start, failure)| {
            if let Some(latency) = failure.timestamp.checked_sub(start.timestamp) {
                let start_event: Start =
                    serde_json::from_value(start.value.clone()).expect("could not parse JSON");
                let fail_event: Failure =
                    serde_json::from_value(failure.value.clone()).expect("could not parse JSON");
                failure_join_predicate(start_event, fail_event, latency)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    (success_stats, failure_stats)
}

/// Helper struct for storing computed data about outgoing and incoming
/// payments.
#[derive(Debug, Default)]
pub struct StructuredPaymentEvents {
    outgoing_latencies: Vec<u64>,
    incoming_latencies: Vec<u64>,
    outgoing_fees: Vec<Amount>,
    incoming_fees: Vec<Amount>,
    outgoing_latencies_failure: Vec<u64>,
    incoming_latencies_failure: Vec<u64>,
}

impl StructuredPaymentEvents {
    pub fn new(
        outgoing_success_stats: &[(u64, Amount)],
        incoming_success_stats: &[(u64, Amount)],
        outgoing_failure_stats: Vec<u64>,
        incoming_failure_stats: Vec<u64>,
    ) -> StructuredPaymentEvents {
        let mut events = StructuredPaymentEvents {
            outgoing_latencies: outgoing_success_stats.iter().map(|(l, _)| *l).collect(),
            incoming_latencies: incoming_success_stats.iter().map(|(l, _)| *l).collect(),
            outgoing_fees: outgoing_success_stats.iter().map(|(_, f)| *f).collect(),
            incoming_fees: incoming_success_stats.iter().map(|(_, f)| *f).collect(),
            outgoing_latencies_failure: outgoing_failure_stats,
            incoming_latencies_failure: incoming_failure_stats,
        };
        events.sort();
        events
    }

    /// Combines this `StructuredPaymentEvents` with the `other`
    /// `StructuredPaymentEvents` by appending all of the internal vectors.
    pub fn combine(&mut self, other: &mut StructuredPaymentEvents) {
        self.outgoing_latencies
            .append(&mut other.outgoing_latencies);
        self.incoming_latencies
            .append(&mut other.incoming_latencies);
        self.outgoing_fees.append(&mut other.outgoing_fees);
        self.incoming_fees.append(&mut other.incoming_fees);
        self.outgoing_latencies_failure
            .append(&mut other.outgoing_latencies_failure);
        self.incoming_latencies_failure
            .append(&mut other.incoming_latencies_failure);
        self.sort();
    }

    /// Sorts this `StructuredPaymentEvents` by sorting all of the internal
    /// vectors.
    fn sort(&mut self) {
        self.outgoing_latencies.sort_unstable();
        self.incoming_latencies.sort_unstable();
        self.outgoing_fees.sort_unstable();
        self.incoming_fees.sort_unstable();
        self.outgoing_latencies_failure.sort_unstable();
        self.incoming_latencies_failure.sort_unstable();
    }

    /// Computes a `PaymentSummaryResponse` that can display at a glance
    /// statistics about the outgoing and incoming payments.
    pub fn payment_summary_response(&self) -> PaymentSummaryResponse {
        PaymentSummaryResponse {
            outgoing: Self::compute_payment_stats(
                &self.outgoing_latencies,
                &self.outgoing_fees,
                &self.outgoing_latencies_failure,
            ),
            incoming: Self::compute_payment_stats(
                &self.incoming_latencies,
                &self.incoming_fees,
                &self.incoming_latencies_failure,
            ),
        }
    }

    /// Computes the payment statistics for the given input data.
    fn compute_payment_stats(
        latencies: &[u64],
        fees: &[Amount],
        latencies_failure: &[u64],
    ) -> PaymentStats {
        PaymentStats {
            average_latency_micros: average(latencies),
            median_latency_micros: median(latencies),
            total_fees: Amount::from_msats(fees.iter().map(|a| a.msats).sum()),
            total_success: latencies.len(),
            total_failure: latencies_failure.len(),
        }
    }
}

/// Computes the average of the given `u64` slice.
fn average(data: &[u64]) -> u64 {
    let sum: u64 = data.iter().sum();
    if data.is_empty() {
        0
    } else {
        sum / data.len() as u64
    }
}

/// Computes the median of the given `u64` slice.
fn median(data: &[u64]) -> u64 {
    if data.is_empty() {
        return 0;
    }

    let length = data.len();
    if length % 2 == 0 {
        data[length / 2 - 1]
    } else {
        data[length / 2]
    }
}
