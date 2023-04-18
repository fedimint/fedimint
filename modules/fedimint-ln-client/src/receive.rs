use fedimint_core::encoding::{Decodable, Encodable};

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that waits on the receipt of a Lightning payment.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     CreateAndSubmitOffer -- await transaction timeout --> Aborted
///     CreateAndSubmitOffer -- await invoice confirmation --> ConfirmedInvoice
///     ConfirmedInvoice -- await claim transaction acceptance  --> Funded
///     ConfirmedInvoice -- await claim transaction timeout --> Aborted
///     Funded -- await preimage decryption --> Preimage
///     Funded -- await preimage decryption failure --> Aborted
///     Preimage -- claim funds --> Paid
///     Preimage -- claim funds failure --> Aborted
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum LnReceiveStates {}
