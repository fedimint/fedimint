use fedimint_core::db::DatabaseError;
#[cfg(not(target_family = "wasm"))]
use fedimint_db_locked::DbLockError;

/// Why [`MemAndRedb::new`](crate::MemAndRedb::new) could not open a database.
///
/// The first three variants exist on native targets only.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MemAndRedbOpenError {
    /// The database path has no parent directory to create.
    #[cfg(not(target_family = "wasm"))]
    #[error("db path must have a base dir")]
    NoBaseDir,

    /// The parent directory of the database could not be created.
    #[cfg(not(target_family = "wasm"))]
    #[error(transparent)]
    CreateDir(#[from] std::io::Error),

    /// The lock file next to the database could not be opened or locked.
    #[cfg(not(target_family = "wasm"))]
    #[error(transparent)]
    Lock(#[from] DbLockError),

    /// A database in the redb v2 file format could not be opened to migrate
    /// it.
    #[error("Failed to open redb v2 database for migration")]
    OpenV2(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A database in the redb v2 file format could not be upgraded to v3.
    #[error("Failed to upgrade redb database to v3 format")]
    UpgradeV2(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The database could not be opened after its migration to the v3 format.
    #[error("Failed to open redb database after v2->v3 migration")]
    OpenMigrated(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The database could not be created or opened.
    #[error("Failed to create/open redb database")]
    Open(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The content of the database could not be loaded into memory.
    #[error(transparent)]
    Load(#[from] DatabaseError),
}
