use std::path::{Path, PathBuf};

use fedimint_core::db::IRawDatabase;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_DB;
use tracing::{debug, info};

/// Locked version of database
///
/// This will use file-system advisory locks to prevent to
/// serialize opening and using the `DB`.
///
/// Use [`LockedBuilder`] to create.
#[derive(Debug)]
pub struct Locked<DB> {
    inner: DB,
    #[allow(dead_code)] // only for `Drop`
    lock: fs_lock::FileLock,
}

/// Builder for [`Locked`]
pub struct LockedBuilder {
    lock: fs_lock::FileLock,
}

impl LockedBuilder {
    /// Create a [`Self`] by acquiring a lock file
    pub fn new(db_path: &Path) -> Result<LockedBuilder, DbLockError> {
        let lock_path = db_path.with_extension("db.lock");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)
            .map_err(|source| DbLockError::Open {
                path: lock_path.clone(),
                source,
            })?;

        debug!(target: LOG_DB, lock=%lock_path.display(), "Acquiring database lock");

        let lock = match fs_lock::FileLock::new_try_exclusive(file) {
            Ok(lock) => lock,
            Err((file, _)) => {
                info!(target: LOG_DB, lock=%lock_path.display(), "Waiting for the database lock");

                fs_lock::FileLock::new_exclusive(file).map_err(DbLockError::Acquire)?
            }
        };
        debug!(target: LOG_DB, lock=%lock_path.display(), "Acquired database lock");

        Ok(LockedBuilder { lock })
    }

    /// Create [`Locked`] by giving it the database to wrap; fails with the
    /// error of `db_fn`.
    pub fn with_db<DB, E>(self, db_fn: impl FnOnce() -> Result<DB, E>) -> Result<Locked<DB>, E> {
        Ok(Locked {
            inner: db_fn()?,
            lock: self.lock,
        })
    }
}

/// Why [`LockedBuilder::new`] could not lock a database.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DbLockError {
    /// The lock file next to the database could not be opened or created.
    #[error("Failed to open {}", path.display())]
    Open {
        /// The path of the lock file.
        path: PathBuf,
        /// Why it could not be opened.
        #[source]
        source: std::io::Error,
    },

    /// Waiting for the exclusive lock on the lock file failed.
    #[error("Failed to acquire a lock file")]
    Acquire(#[source] std::io::Error),
}

#[apply(async_trait_maybe_send!)]
impl<DB> IRawDatabase for Locked<DB>
where
    DB: IRawDatabase,
{
    type Transaction<'a> = DB::Transaction<'a>;

    async fn begin_transaction<'a>(
        &'a self,
    ) -> <Locked<DB> as fedimint_core::db::IRawDatabase>::Transaction<'_> {
        self.inner.begin_transaction().await
    }

    fn checkpoint(&self, backup_path: &Path) -> fedimint_core::db::DatabaseResult<()> {
        self.inner.checkpoint(backup_path)
    }
}
