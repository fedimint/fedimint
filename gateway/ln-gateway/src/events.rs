use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use fedimint_client::ClientHandle;
use fedimint_core::core::ModuleKind;
use fedimint_core::time::now;
use fedimint_eventlog::{DBTransactionEventLogExt, Event, EventKind, EventLogId};
use fedimint_mint_client::event::{OOBNotesReissued, OOBNotesSpent};
use fedimint_wallet_client::events::{DepositConfirmed, WithdrawRequest};

use crate::gateway_module_v2::events::{
    CompleteLightningPaymentSucceeded, IncomingPaymentFailed, IncomingPaymentStarted,
    IncomingPaymentSucceeded, OutgoingPaymentFailed, OutgoingPaymentStarted,
    OutgoingPaymentSucceeded,
};

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

pub type LogEntry = (
    EventLogId,
    EventKind,
    Option<(ModuleKind, u16)>,
    u64,
    serde_json::Value,
);

pub async fn get_last_day_events(client: &Arc<ClientHandle>) -> Vec<LogEntry> {
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

fn get_earliest_index(batch: &Vec<LogEntry>) -> usize {
    let one_day_ago = now()
        .checked_sub(Duration::from_secs(60 * 60 * 24))
        .expect("outside valid SystemTime bounds");
    let timestamps = batch.iter().map(|e| e.3).collect::<Vec<_>>();
    let one_day_ago_micros = one_day_ago
        .duration_since(UNIX_EPOCH)
        .expect("before unix epoch")
        .as_micros() as u64;
    let index = timestamps.binary_search(&one_day_ago_micros);
    let index = match index {
        Ok(index) => index,
        Err(index) => index,
    };
    index
}

// TODO: Add Gateway specific events
