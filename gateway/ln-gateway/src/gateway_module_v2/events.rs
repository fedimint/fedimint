use std::iter::zip;
use std::time::SystemTime;

use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleKind;
use fedimint_core::Amount;
use fedimint_eventlog::{Event, EventKind};
use fedimint_lnv2_common::contracts::{Commitment, OutgoingContract, PaymentImage};
use serde::{Deserialize, Serialize};
use serde_millis;

use super::send_sm::Cancelled;
use crate::events::{FilteredPaymentEvents, LogEntry, StructuredPaymentEvents};

/// Event that is emitted when an outgoing payment attempt is initiated.
#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentStarted {
    /// The timestamp that the operation begins, including the API calls to the
    /// federation to get the consensus block height.
    #[serde(with = "serde_millis")]
    pub operation_start: SystemTime,

    /// The outgoing contract for this payment.
    pub outgoing_contract: OutgoingContract,

    /// The minimum amount that must be escrowed for the payment (includes the
    /// gateway's fee)
    pub min_contract_amount: Amount,

    /// The amount requested in the invoice.
    pub invoice_amount: Amount,

    /// The max delay of the payment in blocks.
    pub max_delay: u64,
}

impl Event for OutgoingPaymentStarted {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-started");
}

/// Event that is emitted when an outgoing payment attempt has succeeded.
#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentSucceeded {
    /// The payment image of the invoice that was paid.
    pub payment_image: PaymentImage,

    /// The target federation ID if a swap was performed, otherwise `None`.
    pub target_federation: Option<FederationId>,
}

impl Event for OutgoingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-succeeded");
}

/// Event that is emitted when an outgoing payment attempt has failed.
#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentFailed {
    /// The payment image of the invoice that failed.
    pub payment_image: PaymentImage,

    /// The reason the outgoing payment was cancelled.
    pub error: Cancelled,
}

impl Event for OutgoingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-failed");
}

/// Event that is emitted when an incoming payment attempt has started. Includes
/// both internal swaps and outside LN payments.
#[derive(Serialize, Deserialize)]
pub struct IncomingPaymentStarted {
    /// The timestamp that the operation begins, including any metadata checks
    /// before the state machine has spawned.
    #[serde(with = "serde_millis")]
    pub operation_start: SystemTime,

    /// The commitment for the incoming contract.
    pub incoming_contract_commitment: Commitment,

    /// The amount requested in the invoice.
    pub invoice_amount: Amount,
}

impl Event for IncomingPaymentStarted {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("incoming-payment-started");
}

/// Event that is emitted when an incoming payment attempt has succeeded.
/// Includes both internal swaps and outside LN payments.
#[derive(Serialize, Deserialize)]
pub struct IncomingPaymentSucceeded {
    /// The payment image of the invoice that was paid.
    pub payment_image: PaymentImage,
}

impl Event for IncomingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("incoming-payment-succeeded");
}

/// Event that is emitted when an incoming payment attempt has failed.
#[derive(Serialize, Deserialize)]
pub struct IncomingPaymentFailed {
    /// The payment image of the invoice that failed
    pub payment_image: PaymentImage,

    /// The reason the incoming payment failed
    pub error: String,
}

impl Event for IncomingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("incoming-payment-failed");
}

/// Event that is emitted when a preimage is revealed to the Lightning network.
/// Only emitted for payments that are received from an external Lightning node,
/// not internal swaps.
#[derive(Serialize, Deserialize)]
pub struct CompleteLightningPaymentSucceeded {
    /// The payment image of the invoice that was paid.
    pub payment_image: PaymentImage,
}

impl Event for CompleteLightningPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);

    const KIND: EventKind = EventKind::from_static("complete-lightning-payment-succeeded");
}

pub fn compute_lnv2_stats(all_events: Vec<LogEntry>) -> StructuredPaymentEvents {
    let lnv2_events = filter_lnv2_events(all_events);
    let (outgoing_success_stats, outgoing_failure_stats) = join_outgoing_lnv2_events(
        &lnv2_events.outgoing_start_events,
        &lnv2_events.outgoing_success_events,
        &lnv2_events.outgoing_failure_events,
    );

    let (incoming_success_stats, incoming_failure_stats) = join_incoming_lnv2_events(
        &lnv2_events.incoming_start_events,
        &lnv2_events.incoming_success_events,
        &lnv2_events.incoming_failure_events,
    );

    StructuredPaymentEvents::new(
        outgoing_success_stats,
        incoming_success_stats,
        outgoing_failure_stats,
        incoming_failure_stats,
    )
}

// TODO: Can we improve this by not cloning every time?
// TODO: Make this a macro?
fn filter_lnv2_events(all_events: Vec<LogEntry>) -> FilteredPaymentEvents {
    let outgoing_start_events = all_events
        .clone()
        .into_iter()
        .filter_map(|e| {
            if let Some((m, _)) = &e.2 {
                if e.1 == OutgoingPaymentStarted::KIND && *m == fedimint_lnv2_common::KIND {
                    Some(e)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let outgoing_success_events = all_events
        .clone()
        .into_iter()
        .filter_map(|e| {
            if let Some((m, _)) = &e.2 {
                if e.1 == OutgoingPaymentSucceeded::KIND && *m == fedimint_lnv2_common::KIND {
                    Some(e)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let outgoing_failure_events = all_events
        .clone()
        .into_iter()
        .filter_map(|e| {
            if let Some((m, _)) = &e.2 {
                if e.1 == OutgoingPaymentFailed::KIND && *m == fedimint_lnv2_common::KIND {
                    Some(e)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let incoming_start_events = all_events
        .clone()
        .into_iter()
        .filter_map(|e| {
            if let Some((m, _)) = &e.2 {
                if e.1 == IncomingPaymentStarted::KIND && *m == fedimint_lnv2_common::KIND {
                    Some(e)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let incoming_success_events = all_events
        .clone()
        .into_iter()
        .filter_map(|e| {
            if let Some((m, _)) = &e.2 {
                if e.1 == IncomingPaymentSucceeded::KIND && *m == fedimint_lnv2_common::KIND {
                    Some(e)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let incoming_failure_events = all_events
        .into_iter()
        .filter_map(|e| {
            if let Some((m, _)) = &e.2 {
                if e.1 == IncomingPaymentFailed::KIND && *m == fedimint_lnv2_common::KIND {
                    Some(e)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    FilteredPaymentEvents {
        outgoing_start_events,
        outgoing_success_events,
        outgoing_failure_events,
        incoming_start_events,
        incoming_success_events,
        incoming_failure_events,
    }
}

fn join_outgoing_lnv2_events(
    start_events: &Vec<LogEntry>,
    success_events: &Vec<LogEntry>,
    failure_events: &Vec<LogEntry>,
) -> (Vec<(u64, Amount)>, Vec<u64>) {
    let success_stats = zip(start_events, success_events)
        .filter_map(|(start, success)| {
            let start_event: OutgoingPaymentStarted =
                serde_json::from_value(start.4.clone()).expect("could not parse JSON");
            let success_event: OutgoingPaymentSucceeded =
                serde_json::from_value(success.4.clone()).expect("could not parse JSON");
            if start_event.outgoing_contract.payment_image == success_event.payment_image {
                let latency = success.3 - start.3;
                let fee = start_event
                    .min_contract_amount
                    .checked_sub(start_event.invoice_amount);
                if let Some(fee) = fee {
                    Some((latency, fee))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let failure_stats = zip(start_events, failure_events)
        .filter_map(|(start, success)| {
            let start_event: OutgoingPaymentStarted =
                serde_json::from_value(start.4.clone()).expect("could not parse JSON");
            let fail_event: OutgoingPaymentFailed =
                serde_json::from_value(success.4.clone()).expect("could not parse JSON");
            if start_event.outgoing_contract.payment_image == fail_event.payment_image {
                let latency = success.3 - start.3;
                Some(latency)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    (success_stats, failure_stats)
}

fn join_incoming_lnv2_events(
    start_events: &Vec<LogEntry>,
    success_events: &Vec<LogEntry>,
    failure_events: &Vec<LogEntry>,
) -> (Vec<(u64, Amount)>, Vec<u64>) {
    let success_stats = zip(start_events, success_events)
        .filter_map(|(start, success)| {
            let start_event: IncomingPaymentStarted =
                serde_json::from_value(start.4.clone()).expect("could not parse JSON");
            let success_event: IncomingPaymentSucceeded =
                serde_json::from_value(success.4.clone()).expect("could not parse JSON");
            if start_event.incoming_contract_commitment.payment_image == success_event.payment_image
            {
                let latency = success.3 - start.3;
                let fee = start_event
                    .invoice_amount
                    .checked_sub(start_event.incoming_contract_commitment.amount);
                if let Some(fee) = fee {
                    Some((latency, fee))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let failure_stats = zip(start_events, failure_events)
        .filter_map(|(start, success)| {
            let start_event: IncomingPaymentStarted =
                serde_json::from_value(start.4.clone()).expect("could not parse JSON");
            let fail_event: IncomingPaymentFailed =
                serde_json::from_value(success.4.clone()).expect("could not parse JSON");
            if start_event.incoming_contract_commitment.payment_image == fail_event.payment_image {
                let latency = success.3 - start.3;
                Some(latency)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    (success_stats, failure_stats)
}
