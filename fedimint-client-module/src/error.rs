//! Error types shared between the client and its modules.
//!
//! The client implements the traits in [`crate::module`] and [`crate`] for its
//! modules, so the failures those traits report have to be nameable from both
//! sides; they live here rather than in `fedimint-client`, which the modules do
//! not depend on.

use fedimint_core::core::{ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::DatabaseError;
use fedimint_core::module::AmountUnit;
use thiserror::Error;

use crate::AddStateMachinesError;

/// An operation with the same id already exists in the operation log.
#[derive(Debug, Error)]
#[error("An operation with id {} already exists", .operation_id.fmt_short())]
pub struct OperationAlreadyExistsError {
    /// The id that is already taken.
    pub operation_id: OperationId,
}

/// No operation with the requested id exists in the operation log.
#[derive(Debug, Error)]
#[error("No operation with id {}", .operation_id.fmt_short())]
pub struct OperationNotFoundError {
    /// The id that was looked up.
    pub operation_id: OperationId,
}

/// A failure to look up one of a module's own operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OperationLookupError {
    /// The operation log has no entry with this id.
    #[error("The operation does not exist")]
    NotFound(#[from] OperationNotFoundError),

    /// The operation exists, but was started by a different module.
    #[error(
        "Operation {} was started by module {found}, not {expected}",
        .operation_id.fmt_short()
    )]
    WrongModuleKind {
        /// The operation that was looked up.
        operation_id: OperationId,
        /// The kind of the module doing the lookup.
        expected: ModuleKind,
        /// The kind of the module that started the operation.
        found: String,
    },
}

/// A failure to build, submit or complete a client transaction.
///
/// Covers the whole path a transaction takes on the client: balancing it with
/// the primary module, recording its operation, registering its state machines,
/// and waiting for the primary module's outputs to finalize. Submission to the
/// federation itself is driven by a state machine and is not reported here.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransactionSubmitError {
    /// The operation the transaction would be recorded under already exists.
    #[error("The operation already exists")]
    OperationAlreadyExists(#[from] OperationAlreadyExistsError),

    /// The finalized transaction is larger than the federation accepts.
    #[error("The transaction is {size} bytes, over the limit of {max}")]
    TransactionTooLarge {
        /// The size of the encoded transaction.
        size: usize,
        /// The largest transaction the federation accepts.
        max: usize,
    },

    /// No primary module can hold funds of this unit, so the transaction
    /// cannot be balanced.
    #[error("No primary module for unit {unit:?}")]
    NoPrimaryModule {
        /// The unit that could not be balanced.
        unit: AmountUnit,
    },

    /// The primary module failed to balance the transaction or to complete
    /// its outputs.
    // The boxed cause narrows to `ClientModuleError` once the module->client
    // trait boundary is typed (#8821 part E).
    #[error("The primary module failed")]
    PrimaryModule(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Writing the transaction to the database failed.
    #[error("Database error")]
    Database(#[from] DatabaseError),

    /// The transaction's state machines could not be registered.
    #[error("Failed to add the transaction's state machines")]
    StateMachines(#[from] AddStateMachinesError),
}

/// A failure to find a module able to serve a request.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ModuleLookupError {
    /// The client was not built with a module of this kind, or the federation
    /// does not offer one.
    #[error("No module of kind {kind} found")]
    NoModuleOfKind {
        /// The kind that was asked for.
        kind: ModuleKind,
    },

    /// The client has no module with this instance id.
    #[error("Unknown module instance {instance_id}")]
    UnknownInstance {
        /// The instance id that was asked for.
        instance_id: ModuleInstanceId,
    },

    /// The module instance exists, but is not of the requested type.
    #[error("Module instance {instance_id} is not of type {expected}")]
    WrongModuleType {
        /// The instance that was asked for.
        instance_id: ModuleInstanceId,
        /// The Rust type the caller asked the instance to be.
        expected: &'static str,
    },

    /// No primary module can hold funds of this unit.
    #[error("No primary module for unit {unit:?}")]
    NoPrimaryModule {
        /// The unit that has no primary module.
        unit: AmountUnit,
    },
}

#[cfg(feature = "uniffi")]
impl From<ModuleLookupError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: ModuleLookupError) -> Self {
        Self::General(e.to_string())
    }
}
