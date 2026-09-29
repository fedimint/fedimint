use fedimint_core::OutPoint;
use fedimint_core::encoding::{Decodable, Encodable};

use super::{
    LightningPayCreatedOutgoingLnContract, LightningPayFunded, LightningPayRefund,
    LightningPayRefundable,
};

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that requests the lightning gateway to pay an invoice on
/// behalf of a federation client.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///  CreatedOutgoingLnContract -- await transaction failed --> Canceled
///  CreatedOutgoingLnContract -- await transaction acceptance --> Funded
///  Funded -- await gateway payment success  --> Success
///  Funded -- await gateway cancel payment --> Refund
///  Funded -- await payment timeout --> Refund
///  Funded -- unrecoverable payment error --> Failure
///  Refundable -- gateway issued refunded --> Refund
///  Refundable -- transaction timeout --> Refund
/// ```
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum LightningPayStates {
    CreatedOutgoingLnContract(LightningPayCreatedOutgoingLnContract),
    FundingRejected,
    Funded(LightningPayFunded),
    Success(String),
    #[deprecated(
        since = "0.4.0",
        note = "Pay State Machine skips over this state and will retry payments until cancellation or timeout"
    )]
    Refundable(LightningPayRefundable),
    Refund(LightningPayRefund),
    #[deprecated(
        since = "0.4.0",
        note = "Pay State Machine does not need to wait for the refund tx to be accepted"
    )]
    Refunded(Vec<OutPoint>),
    Failure(String),
}
