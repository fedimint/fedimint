use thiserror::Error;

pub mod modules {
    pub use fedimint_ln as ln;
    pub use fedimint_mint as mint;
    pub use fedimint_wallet as wallet;
}

/// Fedimint toplevel config
pub mod config;
pub mod epoch;
pub mod outcome;
pub mod transaction;
pub mod util;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Mismatching outcome variant: expected {0}, got {1}")]
    MismatchingVariant(&'static str, &'static str),
    #[error("Pending preimage decryption")]
    PendingPreimage,
}

impl CoreError {
    /// Returns `true` if queried outpoint isn't ready yet but may become ready later
    pub fn is_retryable(&self) -> bool {
        matches!(self, CoreError::PendingPreimage)
    }
}
