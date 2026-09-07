//! Error types of the client.
//!
//! The types the client's *modules* also need are defined in
//! [`fedimint_client_module::error`] and re-exported here, so this module is
//! the single place to look.

pub use fedimint_client_module::error::*;
use fedimint_core::encoding::DecodeError;
use thiserror::Error;

/// A failure to read or write the client's stored root secret.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientSecretError {
    /// The database already holds a secret, which is never overwritten.
    #[error("An encoded client secret already exists and cannot be overwritten")]
    AlreadyExists,

    /// The database holds no secret.
    #[error("No encoded client secret is present in the database")]
    NotPresent,

    /// The stored secret is not a valid encoding of the requested type.
    #[error("The stored client secret could not be decoded")]
    Decode(#[from] DecodeError),
}
