//! Error types of the wallet client.
//!
//! Every failure this module reports to its callers is named here, so there is
//! one place for an integrator to look.

use fedimint_core::core::OperationId;
use fedimint_core::db::DatabaseError;
use thiserror::Error;

use crate::client_db::TweakIdx;

/// A failure to look up or drive one of this client's deposit addresses.
///
/// The peg-in side of the wallet is address-oriented: a caller names a deposit
/// by its address, by the operation that allocated it, or by the tweak index
/// behind both, and then waits for the federation to claim what was sent
/// there. Every way that can go wrong is named here.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PegInError {
    /// The address is not one this client derived.
    #[error("The address is not one of this client's deposit addresses")]
    AddressNotDerived,

    /// No deposit address was allocated under this operation.
    #[error("No deposit address belongs to operation {}", .operation_id.fmt_short())]
    OperationNotFound {
        /// The operation that was looked up.
        operation_id: OperationId,
    },

    /// The client has no record of this deposit address index.
    #[error("No deposit address is recorded for {tweak_idx}")]
    TweakIdxNotFound {
        /// The index that was looked up.
        tweak_idx: TweakIdx,
    },

    /// The database write that schedules the re-check failed.
    #[error("Database error")]
    Database(#[from] DatabaseError),

    /// The federation rejected the transaction that would have claimed the
    /// deposit.
    ///
    /// The payload is the message the submission recorded rather than an error
    /// value, so it is part of this error's own message.
    #[error("The transaction claiming the deposit was rejected: {reason}")]
    TransactionRejected {
        /// What the submission reported.
        reason: String,
    },

    /// The peg-in monitor stopped, so no further deposit will ever be claimed.
    #[error("The peg-in monitor is no longer running")]
    MonitorStopped,
}
