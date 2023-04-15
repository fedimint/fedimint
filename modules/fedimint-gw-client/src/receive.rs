use fedimint_core::encoding::{Decodable, Encodable};

/// State machine that handles an intercepted HTLC from the Lightning node.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    HTLCIntercepted -- await preimage offer accepted --> BuyPreimage
///    HTLCIntercepted -- await preimage offer failed --> CancelHTLC
///    BuyPreimage -- await preimage decryption --> Preimage
///    BuyPreimage -- await preimage decryption failure --> CancelHTLC
///    Preimage -- settle HTLC --> Settled
///    Preimage -- settle HTLC failure --> Preimage
///    CancelHTLC -- cancel success --> Canceled
///    CancelHTLC -- cancel failure --> CancelHTLC
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GwReceiveStates {}
