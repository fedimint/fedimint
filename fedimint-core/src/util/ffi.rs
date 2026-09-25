use bech32::segwit::DecodeError;
use lightning_invoice::CreationError;

/// Shared UniFFI error type used across all Fedimint client modules.
///
/// Defined once here so every module crate can import
/// `fedimint_core::UniffiError` instead of each declaring its own error enum.
///
/// Implements `std::error::Error` (via `thiserror`), so `?` converts it into
/// any error type that accepts standard errors.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[cfg_attr(feature = "uniffi", uniffi(flat_error))]
pub enum UniffiError {
    #[error("{0}")]
    General(String),
}

impl From<serde_json::Error> for UniffiError {
    fn from(e: serde_json::Error) -> Self {
        Self::General(e.to_string())
    }
}

impl From<CreationError> for UniffiError {
    fn from(e: CreationError) -> Self {
        Self::General(e.to_string())
    }
}

impl From<DecodeError> for UniffiError {
    fn from(e: DecodeError) -> Self {
        Self::General(e.to_string())
    }
}
