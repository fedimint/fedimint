//! Error types of the lightning client.
//!
//! Every failure this module reports to its callers is named here, so there is
//! one place for an integrator to look.

use fedimint_api_client::api::FederationError;
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
