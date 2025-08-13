use std::time::SystemTime;

use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleKind;
use fedimint_eventlog::{
    Event, EventKind, EventPersistence, PersistedLogEntry, StructuredPaymentEvents,
    filter_events_by_kind, join_events,
};
use fedimint_lnv2_common::contracts::{Commitment, OutgoingContract, PaymentImage};
use serde::{Deserialize, Serialize};
use serde_millis;

use super::send_sm::Cancelled;

/// Event that is emitted when an outgoing payment attempt is initiated.
#[derive(Serialize, Deserialize, Debug)]
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
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when an outgoing payment attempt has succeeded.
#[derive(Serialize, Deserialize, Debug)]
pub struct OutgoingPaymentSucceeded {
    /// The payment image of the invoice that was paid.
    pub payment_image: PaymentImage,

    /// The target federation ID if a swap was performed, otherwise `None`.
    pub target_federation: Option<FederationId>,
}

impl Event for OutgoingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("outgoing-payment-succeeded");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when an outgoing payment attempt has failed.
#[derive(Serialize, Deserialize, Debug)]
pub struct OutgoingPaymentFailed {
    /// The payment image of the invoice that failed.
    pub payment_image: PaymentImage,

    /// The reason the outgoing payment was cancelled.
    pub error: Cancelled,
}

impl Event for OutgoingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("outgoing-payment-failed");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when an incoming payment attempt has started. Includes
/// both internal swaps and outside LN payments.
#[derive(Serialize, Deserialize, Debug)]
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
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when an incoming payment attempt has succeeded.
/// Includes both internal swaps and outside LN payments.
#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingPaymentSucceeded {
    /// The payment image of the invoice that was paid.
    pub payment_image: PaymentImage,
}

impl Event for IncomingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("incoming-payment-succeeded");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when an incoming payment attempt has failed.
#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingPaymentFailed {
    /// The payment image of the invoice that failed
    pub payment_image: PaymentImage,

    /// The reason the incoming payment failed
    pub error: String,
}

impl Event for IncomingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("incoming-payment-failed");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when a preimage is revealed to the Lightning network.
/// Only emitted for payments that are received from an external Lightning node,
/// not internal swaps.
#[derive(Serialize, Deserialize, Debug)]
pub struct CompleteLightningPaymentSucceeded {
    /// The payment image of the invoice that was paid.
    pub payment_image: PaymentImage,
}

impl Event for CompleteLightningPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);
    const KIND: EventKind = EventKind::from_static("complete-lightning-payment-succeeded");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Computes the `StructurePaymentEvents` for all LNv2 payments.
///
/// Filters the event set for LNv2 events and joins them together.
pub fn compute_lnv2_stats(
    all_events: &[PersistedLogEntry],
) -> (StructuredPaymentEvents, StructuredPaymentEvents) {
    let outgoing_start_events = filter_events_by_kind(
        all_events,
        fedimint_lnv2_common::KIND,
        OutgoingPaymentStarted::KIND,
    )
    .collect::<Vec<_>>();
    let outgoing_success_events = filter_events_by_kind(
        all_events,
        fedimint_lnv2_common::KIND,
        OutgoingPaymentSucceeded::KIND,
    )
    .collect::<Vec<_>>();
    let outgoing_failure_events = filter_events_by_kind(
        all_events,
        fedimint_lnv2_common::KIND,
        OutgoingPaymentFailed::KIND,
    )
    .collect::<Vec<_>>();

    let outgoing_success_stats =
        join_events::<OutgoingPaymentStarted, OutgoingPaymentSucceeded, (u64, Amount)>(
            &outgoing_start_events,
            &outgoing_success_events,
            |start_event, success_event, latency| {
                if start_event.outgoing_contract.payment_image == success_event.payment_image {
                    start_event
                        .min_contract_amount
                        .checked_sub(start_event.invoice_amount)
                        .map(|fee| (latency, fee))
                } else {
                    None
                }
            },
        )
        .collect::<Vec<_>>();

    let outgoing_failure_stats = join_events::<OutgoingPaymentStarted, OutgoingPaymentFailed, u64>(
        &outgoing_start_events,
        &outgoing_failure_events,
        |start_event, fail_event, latency| {
            if start_event.outgoing_contract.payment_image == fail_event.payment_image {
                Some(latency)
            } else {
                None
            }
        },
    )
    .collect::<Vec<_>>();

    let incoming_start_events = filter_events_by_kind(
        all_events,
        fedimint_lnv2_common::KIND,
        IncomingPaymentStarted::KIND,
    )
    .collect::<Vec<_>>();
    let incoming_success_events = filter_events_by_kind(
        all_events,
        fedimint_lnv2_common::KIND,
        IncomingPaymentSucceeded::KIND,
    )
    .collect::<Vec<_>>();
    let incoming_failure_events = filter_events_by_kind(
        all_events,
        fedimint_lnv2_common::KIND,
        IncomingPaymentFailed::KIND,
    )
    .collect::<Vec<_>>();

    let incoming_success_stats =
        join_events::<IncomingPaymentStarted, IncomingPaymentSucceeded, (u64, Amount)>(
            &incoming_start_events,
            &incoming_success_events,
            |start_event, success_event, latency| {
                if start_event.incoming_contract_commitment.payment_image
                    == success_event.payment_image
                {
                    start_event
                        .invoice_amount
                        .checked_sub(start_event.incoming_contract_commitment.amount)
                        .map(|fee| (latency, fee))
                } else {
                    None
                }
            },
        )
        .collect::<Vec<_>>();

    let incoming_failure_stats = join_events::<IncomingPaymentStarted, IncomingPaymentFailed, u64>(
        &incoming_start_events,
        &incoming_failure_events,
        |start_event, fail_event, latency| {
            if start_event.incoming_contract_commitment.payment_image == fail_event.payment_image {
                Some(latency)
            } else {
                None
            }
        },
    )
    .collect::<Vec<_>>();

    let outgoing = StructuredPaymentEvents::new(&outgoing_success_stats, outgoing_failure_stats);
    let incoming = StructuredPaymentEvents::new(&incoming_success_stats, incoming_failure_stats);
    (outgoing, incoming)
}
