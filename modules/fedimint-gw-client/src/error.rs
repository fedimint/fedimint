//! Error types of the gateway's LNv1 client module.
//!
//! Every failure this module reports to its callers is named here, so there is
//! one place for an integrator to look. The payment errors its state machines
//! persist, [`crate::pay::OutgoingContractError`] and its relatives, stay in
//! [`crate::pay`].

use fedimint_client_module::{AddStateMachinesError, TransactionSubmitError};
use fedimint_core::core::OperationId;
use fedimint_core::db::{AutocommitError, DatabaseError};
use fedimint_lightning::LightningRpcError;
use fedimint_ln_client::incoming::IncomingSmError;
use fedimint_ln_common::contracts::ContractId;
use thiserror::Error;

use crate::UnsafeHtlcExpiry;

/// A failure to fund the incoming contract for an HTLC the gateway intercepted.
///
/// The gateway buys the payment's preimage from the federation by funding the
/// incoming contract that the recipient offered. A replay of an HTLC circuit
/// the gateway already handles is not a failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HandleInterceptedHtlcError {
    /// The Lightning node could not report its current block height, which
    /// the HTLC's expiry is checked against.
    #[error("The Lightning node's block height could not be read")]
    BlockHeight(#[source] LightningRpcError),

    /// The HTLC expires too soon for the gateway to settle it safely.
    #[error("The HTLC expires too soon to be settled safely")]
    UnsafeExpiry(#[from] UnsafeHtlcExpiry),

    /// The federation's offer for this payment could not be turned into an
    /// incoming contract: it did not arrive in time, violates the fee
    /// policy, does not match the HTLC, already has a funded contract, or
    /// the federation could not be asked.
    #[error("The incoming contract could not be created")]
    IncomingContract(#[from] IncomingSmError),

    /// The operation id derived while funding disagrees with the one derived
    /// from the payment hash. This is a bug in this module; it is reported
    /// instead of panicking so that the caller can fail the HTLC back.
    #[error(
        "Operation id derivation must match: {} != {}",
        .derived.fmt_short(),
        .expected.fmt_short()
    )]
    OperationIdMismatch {
        /// The id derived from the payment hash.
        expected: OperationId,
        /// The id the funding step derived.
        derived: OperationId,
    },

    /// The transaction funding the incoming contract could not be built or
    /// submitted.
    #[error("The funding transaction could not be submitted")]
    Transaction(#[from] TransactionSubmitError),
}

/// A failure to fund the incoming contract of a direct swap.
///
/// A direct swap pays an invoice issued in another federation served by this
/// gateway by funding the matching incoming contract in this one, so the
/// payment never touches the Lightning network. Joining a swap that is already
/// under way, or declining to start one, is not a failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HandleDirectSwapError {
    /// The federation's offer for this payment could not be turned into an
    /// incoming contract: it did not arrive in time, violates the fee
    /// policy, does not match the swap, already has a funded contract, or
    /// the federation could not be asked.
    #[error("The incoming contract could not be created")]
    IncomingContract(#[from] IncomingSmError),

    /// The operation id derived while funding disagrees with the one derived
    /// from the payment hash. This is a bug in this module.
    #[error(
        "Operation id derivation must match: {} != {}",
        .derived.fmt_short(),
        .expected.fmt_short()
    )]
    OperationIdMismatch {
        /// The id derived from the payment hash.
        expected: OperationId,
        /// The id the funding step derived.
        derived: OperationId,
    },

    /// The transaction funding the incoming contract could not be built or
    /// submitted.
    #[error("The funding transaction could not be submitted")]
    Transaction(#[from] TransactionSubmitError),

    /// Recording the swap in the database kept failing.
    #[error("Database error")]
    Database(#[from] DatabaseError),
}

impl From<AutocommitError<HandleDirectSwapError>> for HandleDirectSwapError {
    fn from(e: AutocommitError<Self>) -> Self {
        match e {
            AutocommitError::ClosureError { error, .. } => error,
            AutocommitError::CommitFailed { last_error, .. } => Self::Database(last_error),
        }
    }
}

/// A failure to start paying an invoice on behalf of a federation client.
///
/// These are the refusals that happen before the payment's state machine
/// starts. Once it runs, its outcome is reported through
/// [`crate::GatewayClientModule::gateway_subscribe_ln_pay`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GatewayPayInvoiceError {
    /// The invoice carries no amount, so there is nothing to pay.
    #[error("Invoice is missing amount")]
    MissingInvoiceAmount,

    /// The invoice was pruned, and the gateway cannot pay a pruned invoice.
    #[error("The gateway cannot pay the pruned invoice")]
    PrunedInvoiceRejected(#[source] GatewayClientV1Error),

    /// A payment of this contract is already under way, and the request does
    /// not carry the authentication it was started with.
    #[error("Not authorized to receive the preimage for contract {contract_id}")]
    Unauthorized {
        /// The contract the request asked to pay.
        contract_id: ContractId,
    },

    /// The payment's state machine could not be started.
    #[error("Failed to add the payment's state machines")]
    StateMachines(#[source] AddStateMachinesError),

    /// Recording the payment in the database kept failing.
    #[error("Database error")]
    Database(#[from] DatabaseError),
}

impl From<AutocommitError<GatewayPayInvoiceError>> for GatewayPayInvoiceError {
    fn from(e: AutocommitError<Self>) -> Self {
        match e {
            AutocommitError::ClosureError { error, .. } => error,
            AutocommitError::CommitFailed { last_error, .. } => Self::Database(last_error),
        }
    }
}

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
