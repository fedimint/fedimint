//! Error types of the wallet client.
//!
//! Every failure this module reports to its callers is named here, so there is
//! one place for an integrator to look.

use bitcoin::Network;
use fedimint_bitcoind::BitcoinRpcError;
use fedimint_client_module::error::{OperationAlreadyExistsError, OperationLookupError};
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

/// A failure to hand out a deposit address.
///
/// Covers both the plain allocation and the pooled one, which can also lose a
/// race against a deposit landing on the address it was about to reuse.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DepositAddressError {
    /// The client has never been online to confirm that the federation's
    /// wallet module handles every deposit safely.
    #[error("The federation was not verified to support safe deposits")]
    SafeDepositUnverified,

    /// An operation for this deposit address already exists.
    #[error("The deposit address's operation already exists")]
    OperationAlreadyExists(#[from] OperationAlreadyExistsError),

    /// The bitcoin backend would not start watching the address, so a deposit
    /// to it would never be noticed.
    #[error("The bitcoin backend could not watch the deposit address")]
    BitcoinRpc(#[from] BitcoinRpcError),

    /// The deposit address could not be written to the database.
    #[error("Database error")]
    Database(#[from] DatabaseError),

    /// A pooled address vanished from the database between being offered for
    /// reuse and being reused.
    #[error("The pooled deposit address {tweak_idx} disappeared while it was being reused")]
    PooledAddressDisappeared {
        /// The address index that was being reused.
        tweak_idx: TweakIdx,
    },

    /// A deposit landed on a pooled address between it being offered for reuse
    /// and being reused, so it is no longer free.
    #[error("The pooled deposit address {tweak_idx} was used while it was being reused")]
    PooledAddressUsed {
        /// The address index that was being reused.
        tweak_idx: TweakIdx,
    },
}

#[cfg(feature = "uniffi")]
impl From<DepositAddressError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: DepositAddressError) -> Self {
        use fedimint_core::util::FmtCompact as _;

        Self::General(e.fmt_compact().to_string())
    }
}

/// A failure to follow a deposit operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SubscribeDepositError {
    /// The operation could not be looked up, or belongs to another module.
    #[error("The deposit operation could not be looked up")]
    Operation(#[from] OperationLookupError),

    /// The operation exists and belongs to the wallet, but it is a withdrawal
    /// rather than a deposit.
    #[error("The operation is not a deposit")]
    NotADeposit,

    /// The deposit address recorded with the operation is not valid on the
    /// network this client is configured for.
    #[error("The deposit address is not valid on {expected}")]
    WrongNetwork {
        /// The network this client expects.
        expected: Network,
    },

    /// The deposit predates the 0.4 release, is still pending, and has no
    /// state machine left to report progress from.
    #[error("An old pending deposit cannot be subscribed to")]
    OldPendingDeposit,

    /// The deposit predates the 0.4 release and the outcome recorded for it is
    /// not one of the final ones.
    #[error("The recorded outcome of an old deposit is not final")]
    NonFinalOutcome,
}

#[cfg(feature = "uniffi")]
impl From<SubscribeDepositError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: SubscribeDepositError) -> Self {
        use fedimint_core::util::FmtCompact as _;

        Self::General(e.fmt_compact().to_string())
    }
}
