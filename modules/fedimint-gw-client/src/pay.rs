use fedimint_core::encoding::{Decodable, Encodable};

/// State machine that pays a lightning invoice on behalf of a federation user.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    PayInvoice -- validate outgoing contract --> Canceled
///    PayInvoice -- await preimage offer accepted --> BuyPreimage
///    PayInvoice -- await preimage offer failure --> Canceled
///    BuyPreimage -- await federation decryption --> Preimage
///    BuyPreimage -- external payment --> Preimage
///    BuyPreimage -- await buy preimage failure --> Refund
///    Preimage -- await claim outgoing contract --> Outpoint
///    Preimage -- await claim outgoing contract failure --> Refund
///    Refund -- await cancel transaction acceptance --> Refunded
///    Refund -- await cancel transaction failure --> Failure
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GwPayStates {}
