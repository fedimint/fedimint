//! Error types of the gateway's LNv1 client module.
//!
//! Every failure this module reports to its callers is named here, so there is
//! one place for an integrator to look. The payment errors its state machines
//! persist, [`crate::pay::OutgoingContractError`] and its relatives, stay in
//! [`crate::pay`].

use thiserror::Error;

/// A failure reported by the gateway behind [`crate::IGatewayClientV1`].
///
/// The trait is implemented by the gateway, not by this module, so the causes
/// are the gateway's own. This type carries them unchanged: its `Display` and
/// its `source()` are the cause's.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct GatewayClientV1Error(Box<dyn std::error::Error + Send + Sync>);

impl GatewayClientV1Error {
    /// Wraps a failure of the gateway's [`crate::IGatewayClientV1`]
    /// implementation, which may be any error value or a plain message.
    pub fn new<E>(source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self(source.into())
    }
}
