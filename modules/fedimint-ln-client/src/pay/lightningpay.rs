use fedimint_core::OutPoint;
use fedimint_core::encoding::{Decodable, Encodable};

use super::{
    LightningPayCreatedOutgoingLnContract, LightningPayFederationUnreachable,
    LightningPayFederationUnreachableRefundFailed,
    LightningPayFederationUnreachableRefundSubmitted, LightningPayFunded, LightningPayRefund,
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
///  Funded -- federation unreachable --> FederationUnreachablePendingRefund
///  FederationUnreachablePendingRefund -- contract cancelled --> FederationUnreachableRefundSubmitted
///  FederationUnreachablePendingRefund -- contract timeout --> FederationUnreachableRefundSubmitted
///  FederationUnreachableRefundSubmitted -- refund rejected --> FederationUnreachablePendingRefund
///  FederationUnreachableRefundSubmitted -- accepted and outputs finalized --> FederationUnreachable
///  FederationUnreachableRefundSubmitted -- refund output failed --> FederationUnreachableRefundFailed
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
    /// The gateway reported a sanitized gateway-to-federation connectivity
    /// failure; the client is waiting until it can reclaim the contract.
    FederationUnreachablePendingRefund(LightningPayRefundable),
    /// The client submitted the reclaim transaction and is waiting for its
    /// acceptance and primary-module output finalization.
    FederationUnreachableRefundSubmitted(LightningPayFederationUnreachableRefundSubmitted),
    /// The reclaim transaction and its primary-module outputs finalized.
    FederationUnreachable(LightningPayFederationUnreachable),
    /// The reclaim transaction was accepted, but a primary-module output
    /// failed terminally and requires operator recovery.
    FederationUnreachableRefundFailed(LightningPayFederationUnreachableRefundFailed),
}
