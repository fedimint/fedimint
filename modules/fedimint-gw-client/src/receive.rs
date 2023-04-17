use fedimint_core::encoding::{Decodable, Encodable};

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that handles an intercepted HTLC from the Lightning node.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    HTLCIntercepted -- validate HTLC and contract success --> HandleHTLC
///    HTLCIntercepted -- valudate HTLC and contract failure --> CancelHTLC
///    HandleHTLC -- await incoming contract accepted --> Funded
///    HandleHTLC -- await incoming contract failure --> CancelHTLC
///    Funded -- await federation decryption --> Preimage
///    Funded -- await federation decryption failure --> Refund
///    Preimage -- settle HTLC --> Settled
///    Preimage -- settle HTLC failure --> Preimage
///    CancelHTLC -- cancel success --> Canceled
///    CancelHTLC -- cancel failure --> CancelHTLC
///    Refund -- await cancel transaction acceptance --> Refunded
///    Refund -- await cancel transaction failure --> Failure
///    Refunded -- cancel HTLC --> CancelHTLC
///    Preimage -- settle HTLC timeout --> Refund
///    CancelHTLC -- cancel HTLC timeout --> TimeOut
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GwReceiveStates {}
