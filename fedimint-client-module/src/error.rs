//! Error types shared between the client and its modules.
//!
//! The client implements the traits in [`crate::module`] and [`crate`] for its
//! modules, so the failures those traits report have to be nameable from both
//! sides; they live here rather than in `fedimint-client`, which the modules do
//! not depend on.

use fedimint_core::core::{ModuleKind, OperationId};
use thiserror::Error;

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
