//! Error types of the mint client.
//!
//! Every failure this module reports to its callers is named here, including
//! the two types that predate this module and are re-exported from it, so
//! there is one place to look.

use fedimint_core::Amount;
use fedimint_core::config::FederationIdPrefix;
use fedimint_core::encoding::DecodeError;
use thiserror::Error;

pub use crate::{InsufficientBalanceError, ReissueExternalNotesError};

/// A note that cannot be spent.
///
/// Reported both for notes received out of band and for notes already held in
/// the wallet, which is why a decoding failure is one of the conditions.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ValidateNotesError {
    /// The notes were issued by a different federation.
    #[error("The notes were issued by federation {found}, not {expected}")]
    WrongFederationId {
        /// The federation this client belongs to.
        expected: FederationIdPrefix,
        /// The federation the notes name.
        found: FederationIdPrefix,
    },

    /// The note claims a denomination the federation does not issue.
    #[error("Note {index} claims the amount tier {amount}, which the federation does not issue")]
    InvalidAmountTier {
        /// The position of the note in the set that was checked.
        index: usize,
        /// The tier the note claims.
        amount: Amount,
    },

    /// The note does not carry a valid federation signature.
    #[error("Note {index} does not carry a valid federation signature")]
    InvalidSignature {
        /// The position of the note in the set that was checked.
        index: usize,
    },

    /// The note cannot be spent with the key that was supplied with it.
    #[error("Note {index} cannot be spent with the supplied spend key")]
    WrongSpendKey {
        /// The position of the note in the set that was checked.
        index: usize,
    },

    /// A note held in the wallet could not be decoded.
    #[error("A stored note could not be decoded")]
    Decode(#[from] DecodeError),
}

#[cfg(feature = "uniffi")]
impl From<ValidateNotesError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: ValidateNotesError) -> Self {
        use fedimint_core::util::FmtCompact as _;

        Self::General(e.fmt_compact().to_string())
    }
}
