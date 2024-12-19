use std::iter::zip;

use fedimint_core::core::{ModuleKind, OperationId};
use fedimint_core::Amount;
use fedimint_eventlog::{Event, EventKind};
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::ContractId;
use serde::{Deserialize, Serialize};

use super::pay::OutgoingPaymentError;
use crate::events::{FilteredPaymentEvents, LogEntry, StructuredPaymentEvents};

/// LNv1 event that is emitted when an outgoing payment attempt is initiated.
#[derive(Serialize, Deserialize)]
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
}

/// LNv1 event that is emitted when an outgoing payment attempt has succeeded.
#[derive(Serialize, Deserialize)]
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
}

/// LNv1 event that is emitted when an outgoing payment attempt has failed.
#[derive(Serialize, Deserialize)]
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
}

/// LNv1 event that is emitted when an incoming payment attempt has started.
#[derive(Serialize, Deserialize)]
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
}

/// LNv1 event that is emitted when an incoming payment attempt was successful.
#[derive(Serialize, Deserialize)]
pub struct IncomingPaymentSucceeded {
    /// The payment hash of the invoice that was paid.
    pub payment_hash: bitcoin::hashes::sha256::Hash,

    /// The decrypted preimage that was acquired from the federation.
    pub preimage: String,
}

impl Event for IncomingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("incoming-payment-succeeded");
}

/// LNv1 event that is emitted when an incoming payment attempt has failed.
#[derive(Serialize, Deserialize)]
pub struct IncomingPaymentFailed {
    /// The payment hash of the invoice that failed to be paid.
    pub payment_hash: bitcoin::hashes::sha256::Hash,

    /// The reason the incoming payment attempt failed.
    pub error: String,
}

impl Event for IncomingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("incoming-payment-failed");
}

/// LNv1 event that is emitted when a preimage was successfully revealed to the
/// Lightning Network.
#[derive(Serialize, Deserialize)]
pub struct CompleteLightningPaymentSucceeded {
    /// The payment hash of the payment.
    pub payment_hash: bitcoin::hashes::sha256::Hash,
}

impl Event for CompleteLightningPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("complete-lightning-payment-succeeded");
}

pub fn compute_lnv1_stats(all_events: Vec<LogEntry>) -> StructuredPaymentEvents {
    let lnv1_events = filter_lnv1_events(all_events);
    let (outgoing_success_stats, outgoing_failure_stats) = join_outgoing_lnv1_events(
        &lnv1_events.outgoing_start_events,
        &lnv1_events.outgoing_success_events,
        &lnv1_events.outgoing_failure_events,
    );
    let (incoming_success_stats, incoming_failure_stats) = join_incoming_lnv1_events(
        &lnv1_events.incoming_start_events,
        &lnv1_events.incoming_success_events,
        &lnv1_events.incoming_failure_events,
    );

    StructuredPaymentEvents::new(
        outgoing_success_stats,
        incoming_success_stats,
        outgoing_failure_stats,
        incoming_failure_stats,
    )
}

// TODO: Can we improve this by not cloning every time?
fn filter_lnv1_events(all_events: Vec<LogEntry>) -> FilteredPaymentEvents {
    let outgoing_start_events = all_events
        .clone()
        .into_iter()
        .filter_map(|e| {
            if let Some((m, _)) = &e.2 {
                if e.1 == OutgoingPaymentStarted::KIND && *m == fedimint_ln_common::KIND {
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
                if e.1 == OutgoingPaymentSucceeded::KIND && *m == fedimint_ln_common::KIND {
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
                if e.1 == OutgoingPaymentFailed::KIND && *m == fedimint_ln_common::KIND {
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
                if e.1 == IncomingPaymentStarted::KIND && *m == fedimint_ln_common::KIND {
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
                if e.1 == IncomingPaymentSucceeded::KIND && *m == fedimint_ln_common::KIND {
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
                if e.1 == IncomingPaymentFailed::KIND && *m == fedimint_ln_common::KIND {
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

fn join_outgoing_lnv1_events(
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
            if start_event.contract_id == success_event.contract_id {
                let latency = success.3 - start.3;
                let fee = success_event
                    .outgoing_contract
                    .amount
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
            if start_event.contract_id == fail_event.contract_id {
                let latency = success.3 - start.3;
                Some(latency)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    (success_stats, failure_stats)
}

fn join_incoming_lnv1_events(
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
            if start_event.payment_hash == success_event.payment_hash {
                let latency = success.3 - start.3;
                let fee = start_event
                    .contract_amount
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
            let start_event: IncomingPaymentStarted =
                serde_json::from_value(start.4.clone()).expect("could not parse JSON");
            let fail_event: IncomingPaymentFailed =
                serde_json::from_value(success.4.clone()).expect("could not parse JSON");
            if start_event.payment_hash == fail_event.payment_hash {
                let latency = success.3 - start.3;
                Some(latency)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    (success_stats, failure_stats)
}
