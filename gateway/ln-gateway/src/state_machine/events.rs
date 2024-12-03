use fedimint_core::core::ModuleKind;
use fedimint_core::Amount;
use fedimint_eventlog::{Event, EventKind};
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::ContractId;
use serde::{Deserialize, Serialize};

use super::pay::OutgoingPaymentError;

#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentStarted {
    pub contract_id: ContractId,
    pub invoice_amount: Amount,
}

impl Event for OutgoingPaymentStarted {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-started");
}

#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentSucceeded {
    pub outgoing_contract: OutgoingContractAccount,
    pub contract_id: ContractId,
    pub preimage: String,
}

impl Event for OutgoingPaymentSucceeded {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-succeeded");
}

#[derive(Serialize, Deserialize)]
pub struct OutgoingPaymentFailed {
    pub outgoing_contract: OutgoingContractAccount,
    pub contract_id: ContractId,
    pub error: OutgoingPaymentError,
}

impl Event for OutgoingPaymentFailed {
    const MODULE: Option<ModuleKind> = Some(fedimint_ln_common::KIND);

    const KIND: EventKind = EventKind::from_static("outgoing-payment-failed");
}
