use std::path::Path;

use anyhow::Context;
use fedimint_core::db::IRawDatabase;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_CLIENT;
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
    pub async fn new(lock_path: &Path) -> anyhow::Result<LockedBuilder> {
        tokio::task::block_in_place(|| {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(lock_path)
                .with_context(|| format!("Failed to open {}", lock_path.display()))?;

            // TODO: Use https://github.com/cargo-bins/cargo-binstall/pull/1496 to
            // give user feedback only when the initial `new_try_exclusive` failed.
            info!(target: LOG_CLIENT, "Acquiring database lock");
            let lock =
                fs_lock::FileLock::new_exclusive(file).context("Failed to acquire a lock file")?;
            debug!(target: LOG_CLIENT, "Acquired database lock");

            Ok(LockedBuilder { lock })
        })
    }

    /// Create [`Locked`] by giving it the database to wrap
    pub fn with_db<DB>(self, db: DB) -> Locked<DB> {
        Locked {
            inner: db,
            lock: self.lock,
        }
    }
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
}
