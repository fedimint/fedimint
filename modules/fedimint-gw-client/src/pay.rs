use fedimint_core::encoding::{Decodable, Encodable};

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that pays a lightning invoice on behalf of a federation user.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    FetchContract -- fetch/validate contract failed --> Canceled
///    FetchContract -- fetch and validate contract success --> BuyPreimage
///    BuyPreimage -- internal --> InternalPayment
///    BuyPreimage -- external --> ExternalPayment
///    InternalPayment -- await incoming contract acceptance -->Funded
///    InternalPayment -- await incoming contract failure --> Canceled
///    Funded -- await federation decryption --> Preimage
///    Funded -- await federation decryption failure --> Refund
///    ExternalPayment -- lightning payment success --> Preimage
///    ExternalPayment -- lightning payment failure --> Canceled
///    Preimage -- await claim transaction acceptance --> Claimed
///    Preimage -- await claim transaction failure --> Failure
///    Refund -- await cancel transaction acceptance --> Refunded
///    Refund -- await cancel transaction failure --> Failure
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GwPayStates {}
