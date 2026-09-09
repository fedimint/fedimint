//! Error types of the mint client.
//!
//! Every failure this module reports to its callers is named here, including
//! the two types that predate this module and are re-exported from it, so
//! there is one place to look.

use fedimint_api_client::api::FederationError;
use fedimint_client_module::error::{
    AddStateMachinesError, OperationLookupError, TransactionSubmitError,
};
use fedimint_core::Amount;
use fedimint_core::config::FederationIdPrefix;
use fedimint_core::db::DatabaseError;
use fedimint_core::encoding::DecodeError;
use thiserror::Error;

pub use crate::{InsufficientBalanceError, ReissueExternalNotesError};

/// A failure to pick notes out of the wallet for a spend.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SelectNotesError {
    /// The wallet does not hold enough notes to cover the request.
    #[error("The wallet does not hold enough notes")]
    InsufficientBalance(#[from] InsufficientBalanceError),

    /// The requested amount cannot be made exactly from the denominations the
    /// wallet holds. This does not mean the balance is too low.
    #[error("The amount {requested} cannot be made exactly; the closest selection is {selected}")]
    NoExactAmount {
        /// The amount that was asked for.
        requested: Amount,
        /// The total the greedy selection arrived at instead.
        selected: Amount,
    },

    /// A note held in the wallet could not be decoded.
    #[error("A stored note could not be decoded")]
    Decode(#[from] DecodeError),

    /// A note selector implemented outside this crate failed in a way the
    /// other variants do not describe.
    #[error("The note selector failed")]
    Custom(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// A failure to hand e-cash notes out of band.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SpendOOBError {
    /// A spend of zero has nothing to hand out.
    #[error("Zero-amount out-of-band spends are not supported")]
    ZeroAmount,

    /// The notes to hand out could not be picked.
    #[error("The notes to spend could not be selected")]
    NoteSelection(#[from] SelectNotesError),

    /// The state machines that watch for a refund could not be registered.
    #[error("Failed to add the spend's state machines")]
    StateMachines(#[from] AddStateMachinesError),

    /// The spend could not be written to the database.
    #[error("Database error")]
    Database(#[from] DatabaseError),
}

/// A transaction's e-cash outputs did not become spendable.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AwaitOutputFinalizedError {
    /// The federation rejected the transaction, so its outputs never existed.
    #[error("The transaction was rejected")]
    TransactionRejected,

    /// The issuance state machine gave up.
    ///
    /// `reason` is the text the state machine recorded in the client database
    /// when it failed; it is read back here, never rewritten.
    #[error("The notes could not be issued: {reason}")]
    Failed {
        /// What the issuance state machine recorded.
        reason: String,
    },
}

/// A failure to hand out e-cash for a requested amount.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SendOOBNotesError {
    /// The federation could not be reached, so the wallet cannot mint itself
    /// the denominations it is missing.
    #[error("The federation could not be reached")]
    Federation(#[source] Box<FederationError>),

    /// The self-reissue that makes the right denominations failed.
    #[error("The reissue that would make the right denominations failed")]
    Transaction(#[from] TransactionSubmitError),

    /// The spend could not be written to the database.
    #[error("Database error")]
    Database(#[from] DatabaseError),
}

impl From<FederationError> for SendOOBNotesError {
    fn from(source: FederationError) -> Self {
        Self::Federation(Box::new(source))
    }
}

/// A failure to follow a reissue operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SubscribeReissueExternalNotesError {
    /// No mint operation with this id exists.
    #[error("The operation could not be looked up")]
    Operation(#[from] OperationLookupError),

    /// The operation exists, but it is an out-of-band spend.
    #[error("The operation is an out-of-band spend, not a reissuance")]
    NotAReissuance,

    /// The operation records no transaction, which a reissuance always has.
    #[error("The reissue operation records no transaction")]
    NoTransaction,
}

/// A failure to follow an out-of-band spend operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SubscribeSpendNotesError {
    /// No mint operation with this id exists.
    #[error("The operation could not be looked up")]
    Operation(#[from] OperationLookupError),

    /// The operation exists, but it is a reissuance.
    #[error("The operation is a reissuance, not an out-of-band spend")]
    NotAnOutOfBandSpend,
}

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

#[cfg(feature = "uniffi")]
impl From<SpendOOBError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: SpendOOBError) -> Self {
        use fedimint_core::util::FmtCompact as _;

        Self::General(e.fmt_compact().to_string())
    }
}

#[cfg(feature = "uniffi")]
impl From<ReissueExternalNotesError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: ReissueExternalNotesError) -> Self {
        use fedimint_core::util::FmtCompact as _;

        Self::General(e.fmt_compact().to_string())
    }
}

#[cfg(feature = "uniffi")]
impl From<SubscribeReissueExternalNotesError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: SubscribeReissueExternalNotesError) -> Self {
        use fedimint_core::util::FmtCompact as _;

        Self::General(e.fmt_compact().to_string())
    }
}

#[cfg(feature = "uniffi")]
impl From<SubscribeSpendNotesError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: SubscribeSpendNotesError) -> Self {
        use fedimint_core::util::FmtCompact as _;

        Self::General(e.fmt_compact().to_string())
    }
}

/// A string that is not a valid serialization of out-of-band e-cash notes.
///
/// Unlike the other errors in this module this one interpolates its cause into
/// its message: `clap` renders a `FromStr` failure with `Display` alone, and
/// `OOBNotes`' `Deserialize` impl hands it to `serde::de::Error::custom`, which
/// keeps only the message. A cause behind `source()` would be dropped by both.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OOBNotesParseError {
    /// The string is neither base32 with the fedimint prefix nor base64.
    #[error("The e-cash notes are not a well-formed base32 or base64 string")]
    Encoding,

    /// The decoded bytes are not a valid `OOBNotes` encoding.
    #[error("The e-cash notes could not be decoded: {0}")]
    Decode(#[from] DecodeError),

    /// The string decodes, but carries no notes.
    #[error("The e-cash notes are empty")]
    Empty,
}
