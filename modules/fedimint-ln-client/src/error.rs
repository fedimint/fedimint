//! Error types of the lightning client.
//!
//! Every failure this module reports to its callers is named here, so there is
//! one place for an integrator to look.

use fedimint_api_client::api::FederationError;
use fedimint_client_module::error::{OperationLookupError, TransactionSubmitError};
use fedimint_core::secp256k1::PublicKey;
#[cfg(feature = "uniffi")]
use fedimint_core::util::FmtCompact as _;
use thiserror::Error;

/// A failure to pick a Lightning gateway for an operation.
///
/// Choosing a gateway is one question with two entry points: pick the best
/// available one, or look a specific one up. Both can end without a usable
/// answer, either because the federation has no registrations at all or
/// because the ones it has do not respond.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GatewaySelectionError {
    /// The caller named a gateway and that gateway did not answer.
    #[error("Gateway {gateway_id} is offline")]
    Offline {
        /// The gateway the caller asked for.
        gateway_id: PublicKey,
    },

    /// No gateway is registered with the federation, so there is nothing to
    /// choose from.
    #[error("No gateway is registered with the federation")]
    NoGatewaysRegistered,

    /// Gateways are registered, but none of them answered.
    #[error("No registered gateway was reachable")]
    NoneReachable,

    /// The gateway cache could not be refreshed from the federation, so there
    /// is no up-to-date list to choose from.
    #[error("The gateway cache could not be refreshed")]
    Federation(#[source] Box<FederationError>),
}

impl From<FederationError> for GatewaySelectionError {
    fn from(source: FederationError) -> Self {
        Self::Federation(Box::new(source))
    }
}

#[cfg(feature = "uniffi")]
impl From<GatewaySelectionError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: GatewaySelectionError) -> Self {
        Self::General(e.fmt_compact().to_string())
    }
}

/// A failure to work out the largest invoice amount the client could pay in
/// full.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SpendableAmountError {
    /// No gateway could be chosen, so there is no fee schedule to compute
    /// against.
    #[error("No gateway could be selected for the payment")]
    Gateway(#[from] GatewaySelectionError),

    /// Gateway selection succeeded but returned nothing.
    ///
    /// This is defensive: the selection this method performs always either
    /// yields a gateway or fails, so no caller is expected to see it.
    #[error("No gateway is available to send the payment")]
    NoGatewayAvailable,

    /// The balance cannot cover the smallest payable amount plus the gateway
    /// and federation fees, so there is no amount to send.
    #[error("The balance {balance} is too low to send any amount after fees")]
    BalanceTooLow {
        /// The balance the answer was computed against.
        balance: fedimint_core::Amount,
    },

    /// The fee probe failed for a reason unrelated to the balance.
    #[error("The fee quote for the payment failed")]
    Quote(#[source] TransactionSubmitError),
}

/// A failure to follow a lightning operation.
///
/// Every entry point that takes an operation id and reports on it, the pay,
/// receive, claim and recurring-receive subscriptions, the payment-detail
/// lookup and the outgoing-payment await, first has to find the operation and
/// then check that it is the kind of lightning operation being asked about.
/// Both halves are named here, so a caller can tell "I have never seen that
/// operation" from "that operation is a receive, not a payment".
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LnSubscribeError {
    /// The operation could not be looked up, or belongs to another module.
    #[error("The lightning operation could not be looked up")]
    Operation(#[from] OperationLookupError),

    /// The operation belongs to the lightning module, but it is not an
    /// outgoing payment.
    #[error("The operation is not a lightning payment")]
    NotAPayment,

    /// The operation belongs to the lightning module, but it is not a receive.
    #[error("The operation is not a lightning receive")]
    NotAReceive,

    /// The operation belongs to the lightning module, but it is not a claim of
    /// an already-funded incoming contract.
    #[error("The operation is not a lightning claim")]
    NotAClaim,

    /// The operation belongs to the lightning module, but it is not a receive
    /// against a recurring payment code.
    #[error("The operation is not a recurring lightning receive")]
    NotARecurringReceive,

    /// The operation is a payment, but it is settled inside the federation
    /// rather than over Lightning, so it has no external payment states.
    #[error("The operation is an external lightning payment, not an internal one")]
    NotInternalPayment,

    /// The operation is a payment, but it is settled inside the federation, so
    /// it has no Lightning payment states.
    #[error("The operation is an internal lightning payment, not an external one")]
    NotExternalPayment,

    /// The payment's update stream ended without reaching a final state.
    #[error("The outgoing lightning payment did not reach a final state")]
    NoFinalState,
}

#[cfg(feature = "uniffi")]
impl From<LnSubscribeError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: LnSubscribeError) -> Self {
        Self::General(e.fmt_compact().to_string())
    }
}
