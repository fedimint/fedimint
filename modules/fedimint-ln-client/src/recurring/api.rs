use fedimint_core::config::FederationId;
use serde::{Deserialize, Serialize};

use crate::recurring::{PaymentCodeRootKey, RecurringPaymentProtocol};

#[derive(Debug, Clone, PartialOrd, PartialEq, Hash, Serialize, Deserialize)]
pub struct RecurringPaymentRegistrationRequest {
    /// Federation ID in which the invoices should be generated
    pub federation_id: FederationId,
    /// Recurring payment protocol to use
    pub protocol: RecurringPaymentProtocol,
    /// Public key from which other keys will be derived for each generated
    /// invoice
    pub payment_code_root_key: PaymentCodeRootKey,
}

#[derive(Debug, Clone, PartialOrd, PartialEq, Hash, Serialize, Deserialize)]
pub struct RecurringPaymentRegistrationResponse {
    /// Either a BOLT12 offer or LNURL
    pub recurring_payment_code: String,
}
