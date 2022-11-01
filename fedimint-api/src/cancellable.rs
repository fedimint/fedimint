use thiserror::Error;

/// An error used as a "cancelled" marker in [`Cancellable`].
#[derive(Error, Debug)]
#[error("Operation cancelled")]
pub struct Cancelled;

/// Operation that can potentially get cancelled returning no result (e.g. program shutdown).
pub type Cancellable<T> = std::result::Result<T, Cancelled>;
