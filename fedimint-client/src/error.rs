//! Error types of the client.
//!
//! The types the client's *modules* also need are defined in
//! [`fedimint_client_module::error`] and re-exported here, so this module is
//! the single place to look.

use fedimint_api_client::api::ClientConfigDownloadError;
pub use fedimint_client_module::error::*;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{DatabaseError, DbMigrationError};
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

/// A failure to open, join or recover a client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientBuildError {
    /// The database was never joined to a federation.
    #[error("The client database is not initialized")]
    DatabaseNotInitialized,

    /// The database already belongs to a federation and cannot be joined
    /// again.
    #[error("The client database is already initialized")]
    DatabaseAlreadyInitialized,

    /// The secret does not match the one the database was created with.
    #[error("The secret does not match the one this database was created with")]
    SecretMismatch,

    /// The federation's client config could not be downloaded.
    #[error("Failed to download the client config")]
    ConfigDownload(#[source] Box<ClientConfigDownloadError>),

    /// The stored client config could not be decoded with the modules this
    /// client was built with.
    #[error("Failed to decode the client config")]
    ConfigDecode(#[from] DecodeError),

    /// A database migration failed.
    #[error("Failed to migrate the client database")]
    Migration(#[from] DbMigrationError),

    /// A module could not prepare its recovery.
    // The boxed cause narrows to `ClientModuleError` in #8821 part E.
    #[error("Module {instance_id} ({kind}) failed to prepare its recovery")]
    ModuleRecoveryPrepare {
        /// The kind of the module that failed.
        kind: ModuleKind,
        /// The instance of the module that failed.
        instance_id: ModuleInstanceId,
        /// The failure the module reported.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// A module could not be initialized.
    // The boxed cause narrows to `ClientModuleError` in #8821 part E.
    #[error("Module {instance_id} ({kind}) failed to initialize")]
    ModuleInit {
        /// The kind of the module that failed.
        kind: ModuleKind,
        /// The instance of the module that failed.
        instance_id: ModuleInstanceId,
        /// The failure the module reported.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The database write failed.
    #[error("Database error")]
    Database(#[from] DatabaseError),

    /// The client handle was already shut down and cannot be restarted.
    #[error("The client is already stopped")]
    AlreadyStopped,
}

impl From<ClientConfigDownloadError> for ClientBuildError {
    fn from(source: ClientConfigDownloadError) -> Self {
        Self::ConfigDownload(Box::new(source))
    }
}
