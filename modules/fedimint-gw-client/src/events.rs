use fedimint_core::Amount;
use fedimint_core::core::{ModuleKind, OperationId};
use fedimint_eventlog::{
    Event, EventKind, EventPersistence, PersistedLogEntry, StructuredPaymentEvents,
    filter_events_by_kind, join_events,
};
use fedimint_ln_common::contracts::ContractId;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use serde::{Deserialize, Serialize};

use super::pay::OutgoingPaymentError;

/// LNv1 event that is emitted when an outgoing payment attempt is initiated.
#[derive(Serialize, Deserialize, Debug)]
pub struct OutgoingPaymentStarted {
    /// The contract ID that uniquely identifies the outgoing contract.
    pub contract_id: ContractId,

    /// The amount of the invoice that is being paid.
    pub invoice_amount: Amount,

    /// The operation ID of the outgoing payment
    pub operation_id: OperationId,
}

impl Event for OutgoingPaymentStarted {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);
    const KIND: EventKind = EventKind::from_static("outgoing-payment-started");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// LNv1 event that is emitted when an outgoing payment attempt has succeeded.
#[derive(Serialize, Deserialize, Debug)]
pub struct OutgoingPaymentSucceeded {
    /// LNv1 outgoing contract
    pub outgoing_contract: OutgoingContractAccount,

    /// The contract ID that uniquely identifies the outgoing contract.
    pub contract_id: ContractId,

    /// The preimage acquired from successfully paying the invoice.
    pub preimage: String,
}

impl Event for OutgoingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);
    const KIND: EventKind = EventKind::from_static("outgoing-payment-succeeded");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// LNv1 event that is emitted when an outgoing payment attempt has failed.
#[derive(Serialize, Deserialize, Debug)]
pub struct OutgoingPaymentFailed {
    /// LNv1 outgoing contract
    pub outgoing_contract: OutgoingContractAccount,

    /// The contract ID that uniquely identifies the outgoing contract.
    pub contract_id: ContractId,

    /// The reason the outgoing payment failed.
    pub error: OutgoingPaymentError,
}

impl Event for OutgoingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);
    const KIND: EventKind = EventKind::from_static("outgoing-payment-failed");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// LNv1 event that is emitted when an incoming payment attempt has started.
#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingPaymentStarted {
    /// The contract ID that uniquely identifies the incoming contract.
    pub contract_id: ContractId,

    /// The payment hash of the invoice that is being paid.
    pub payment_hash: bitcoin::hashes::sha256::Hash,

    /// The amount specified in the invoice.
    pub invoice_amount: Amount,

    /// The amount offered in the contract.
    pub contract_amount: Amount,

    /// The operation ID of the outgoing payment
    pub operation_id: OperationId,
}

impl Event for IncomingPaymentStarted {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);
    const KIND: EventKind = EventKind::from_static("incoming-payment-started");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// LNv1 event that is emitted when an incoming payment attempt was successful.
#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingPaymentSucceeded {
    /// The payment hash of the invoice that was paid.
    pub payment_hash: bitcoin::hashes::sha256::Hash,

    /// The decrypted preimage that was acquired from the federation.
    pub preimage: String,
}

impl Event for IncomingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);
    const KIND: EventKind = EventKind::from_static("incoming-payment-succeeded");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// LNv1 event that is emitted when an incoming payment attempt has failed.
#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingPaymentFailed {
    /// The payment hash of the invoice that failed to be paid.
    pub payment_hash: bitcoin::hashes::sha256::Hash,

    /// The reason the incoming payment attempt failed.
    pub error: String,
}

impl Event for IncomingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);
    const KIND: EventKind = EventKind::from_static("incoming-payment-failed");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// LNv1 event that is emitted when a preimage was successfully revealed to the
/// Lightning Network.
#[derive(Serialize, Deserialize, Debug)]
pub struct CompleteLightningPaymentSucceeded {
    /// The payment hash of the payment.
    pub payment_hash: bitcoin::hashes::sha256::Hash,
}

impl Event for CompleteLightningPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);
    const KIND: EventKind = EventKind::from_static("complete-lightning-payment-succeeded");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Computes the `StructurePaymentEvents` for all LNv1 payments.
///
/// Filters the event set for LNv1 events and joins them together.
pub fn compute_lnv1_stats(
    all_events: &[PersistedLogEntry],
) -> (StructuredPaymentEvents, StructuredPaymentEvents) {
    let outgoing_start_events = filter_events_by_kind(
        all_events,
        fedimint_ln_common::KIND,
        OutgoingPaymentStarted::KIND,
    )
    .collect::<Vec<_>>();
    let outgoing_success_events = filter_events_by_kind(
        all_events,
        fedimint_ln_common::KIND,
        OutgoingPaymentSucceeded::KIND,
    )
    .collect::<Vec<_>>();
    let outgoing_failure_events = filter_events_by_kind(
        all_events,
        fedimint_ln_common::KIND,
        OutgoingPaymentFailed::KIND,
    )
    .collect::<Vec<_>>();

    let outgoing_success_stats =
        join_events::<OutgoingPaymentStarted, OutgoingPaymentSucceeded, (u64, Amount)>(
            &outgoing_start_events,
            &outgoing_success_events,
            None,
            |start_event, success_event, latency| {
                if start_event.contract_id == success_event.contract_id {
                    success_event
                        .outgoing_contract
                        .amount
                        .checked_sub(start_event.invoice_amount)
                        .map(|fee| (latency.as_millis() as u64, fee))
                } else {
                    None
                }
            },
        )
        .collect::<Vec<_>>();

    let outgoing_failure_stats = join_events::<OutgoingPaymentStarted, OutgoingPaymentFailed, u64>(
        &outgoing_start_events,
        &outgoing_failure_events,
        None,
        |start_event, fail_event, latency| {
            if start_event.contract_id == fail_event.contract_id {
                Some(latency.as_millis() as u64)
            } else {
                None
            }
        },
    )
    .collect::<Vec<_>>();

    let incoming_start_events = filter_events_by_kind(
        all_events,
        fedimint_ln_common::KIND,
        IncomingPaymentStarted::KIND,
    )
    .collect::<Vec<_>>();
    let incoming_success_events = filter_events_by_kind(
        all_events,
        fedimint_ln_common::KIND,
        IncomingPaymentSucceeded::KIND,
    )
    .collect::<Vec<_>>();
    let incoming_failure_events = filter_events_by_kind(
        all_events,
        fedimint_ln_common::KIND,
        IncomingPaymentFailed::KIND,
    )
    .collect::<Vec<_>>();
    let incoming_success_stats =
        join_events::<IncomingPaymentStarted, IncomingPaymentSucceeded, (u64, Amount)>(
            &incoming_start_events,
            &incoming_success_events,
            None,
            |start_event, success_event, latency| {
                if start_event.payment_hash == success_event.payment_hash {
                    start_event
                        .contract_amount
                        .checked_sub(start_event.invoice_amount)
                        .map(|fee| (latency.as_millis() as u64, fee))
                } else {
                    None
                }
            },
        )
        .collect::<Vec<_>>();

    let incoming_failure_stats = join_events::<IncomingPaymentStarted, IncomingPaymentFailed, u64>(
        &incoming_start_events,
        &incoming_failure_events,
        None,
        |start_event, fail_event, latency| {
            if start_event.payment_hash == fail_event.payment_hash {
                Some(latency.as_millis() as u64)
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
