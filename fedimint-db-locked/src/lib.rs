use std::path::Path;

use anyhow::Context;
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
    pub fn new(db_path: &Path) -> anyhow::Result<LockedBuilder> {
        let lock_path = db_path.with_extension("db.lock");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)
            .with_context(|| format!("Failed to open {}", lock_path.display()))?;

        debug!(target: LOG_DB, lock=%lock_path.display(), "Acquiring database lock");

        let lock = match fs_lock::FileLock::new_try_exclusive(file) {
            Ok(lock) => lock,
            Err((file, _)) => {
                info!(target: LOG_DB, lock=%lock_path.display(), "Waiting for the database lock");

                fs_lock::FileLock::new_exclusive(file).context("Failed to acquire a lock file")?
            }
        };
        debug!(target: LOG_DB, lock=%lock_path.display(), "Acquired database lock");

        Ok(LockedBuilder { lock })
    }

    /// Create [`Locked`] by giving it the database to wrap
    pub fn with_db<DB>(
        self,
        db_fn: impl FnOnce() -> anyhow::Result<DB>,
    ) -> anyhow::Result<Locked<DB>> {
        Ok(Locked {
            inner: db_fn()?,
            lock: self.lock,
        })
    }
}

#[apply(async_trait_maybe_send!)]
impl<DB> IRawDatabase for Locked<DB>
where
    DB: IRawDatabase,
{
    type WriteTransaction<'a> = DB::WriteTransaction<'a>;
    type ReadTransaction<'a> = DB::ReadTransaction<'a>;

    async fn begin_write_transaction<'a>(
        &'a self,
    ) -> <Locked<DB> as fedimint_core::db::IRawDatabase>::WriteTransaction<'_> {
        self.inner.begin_write_transaction().await
    }

    async fn begin_read_transaction<'a>(&'a self) -> Self::ReadTransaction<'a> {
        self.inner.begin_read_transaction().await
    }

    fn checkpoint(&self, backup_path: &Path) -> fedimint_core::db::DatabaseResult<()> {
        self.inner.checkpoint(backup_path)
    }
}
