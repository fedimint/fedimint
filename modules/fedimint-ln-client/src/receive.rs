use fedimint_core::encoding::{Decodable, Encodable};

/// State machine that waits on the receipt of a Lightning payment.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     CreateAndSubmitInvoice -- await transaction timeout --> Aborted
///     CreateAndSubmitInvoice -- await decryption error --> CreateAndSubmitInvoice
///     CreateAndSubmitInvoice -- await invoice confirmation --> ConfirmedInvoice
///     ConfirmedInvoice -- await claim transaction acceptance  --> Paid
///     ConfirmedInvoice -- await claim transaction timeout --> Aborted
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum LnReceiveStates {}
