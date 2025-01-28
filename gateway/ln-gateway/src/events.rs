use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fedimint_client::ClientHandle;
use fedimint_core::core::ModuleKind;
use fedimint_core::util::{get_average, get_median};
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
use crate::rpc::PaymentStats;

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
        let mut dbtx = client.db().begin_transaction_nc().await;
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
                if first_event.timestamp < start_micros {
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
            if event.timestamp < start_micros {
                continue;
            }

            if event.timestamp >= end_micros {
                return all_events;
            }

            all_events.push(event);
        }

        batch_start = batch_start.saturating_add(BATCH_SIZE);
    }
}

/// Filters the given `PersistedLogEntry` slice by the `EventKind` and
/// `ModuleKind`.
pub(crate) fn filter_events<'a, I>(
    all_events: I,
    event_kind: EventKind,
    module_kind: ModuleKind,
) -> impl Iterator<Item = &'a PersistedLogEntry> + 'a
where
    I: IntoIterator<Item = &'a PersistedLogEntry> + 'a,
{
    all_events.into_iter().filter(move |e| {
        if let Some((m, _)) = &e.module {
            e.event_kind == event_kind && *m == module_kind
        } else {
            false
        }
    })
}

/// Joins two sets of events on a predicate.
///
/// This function computes a "nested loop join" by first computing the cross
/// product of the start event vector and the success/failure event vectors. The
/// resulting cartesian product is then filtered according to the join predicate
/// supplied in the parameters.
///
/// This function is intended for small data sets. If the data set relations
/// grow, this function should implement a different join algorithm or be moved
/// out of the gateway.
pub(crate) fn join_events<'a, L, R, Res>(
    events_l: &'a [&PersistedLogEntry],
    events_r: &'a [&PersistedLogEntry],
    predicate: impl Fn(L, R, u64) -> Option<Res> + 'a,
) -> impl Iterator<Item = Res> + 'a
where
    L: Event,
    R: Event,
{
    events_l
        .iter()
        .cartesian_product(events_r)
        .filter_map(move |(l, r)| {
            if let Some(latency) = r.timestamp.checked_sub(l.timestamp) {
                let event_l: L =
                    serde_json::from_value(l.value.clone()).expect("could not parse JSON");
                let event_r: R =
                    serde_json::from_value(r.value.clone()).expect("could not parse JSON");
                predicate(event_l, event_r, latency)
            } else {
                None
            }
        })
}

/// Helper struct for storing computed data about outgoing and incoming
/// payments.
#[derive(Debug, Default)]
pub struct StructuredPaymentEvents {
    latencies: Vec<u64>,
    fees: Vec<Amount>,
    latencies_failure: Vec<u64>,
}

impl StructuredPaymentEvents {
    pub fn new(
        success_stats: &[(u64, Amount)],
        failure_stats: Vec<u64>,
    ) -> StructuredPaymentEvents {
        let mut events = StructuredPaymentEvents {
            latencies: success_stats.iter().map(|(l, _)| *l).collect(),
            fees: success_stats.iter().map(|(_, f)| *f).collect(),
            latencies_failure: failure_stats,
        };
        events.sort();
        events
    }

    /// Combines this `StructuredPaymentEvents` with the `other`
    /// `StructuredPaymentEvents` by appending all of the internal vectors.
    pub fn combine(&mut self, other: &mut StructuredPaymentEvents) {
        self.latencies.append(&mut other.latencies);
        self.fees.append(&mut other.fees);
        self.latencies_failure.append(&mut other.latencies_failure);
        self.sort();
    }

    /// Sorts this `StructuredPaymentEvents` by sorting all of the internal
    /// vectors.
    fn sort(&mut self) {
        self.latencies.sort_unstable();
        self.fees.sort_unstable();
        self.latencies_failure.sort_unstable();
    }

    /// Computes the payment statistics for the given input data.
    pub fn compute_payment_stats(&self) -> PaymentStats {
        PaymentStats {
            average_latency: get_average(&self.latencies).map(Duration::from_micros),
            median_latency: get_median(&self.latencies).map(Duration::from_micros),
            total_fees: Amount::from_msats(self.fees.iter().map(|a| a.msats).sum()),
            total_success: self.latencies.len(),
            total_failure: self.latencies_failure.len(),
        }
    }
}
