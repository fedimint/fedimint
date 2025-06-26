use std::path::Path;

use anyhow::{Context as _, Result};
use fedimint_db_locked::{Locked, LockedBuilder};
use redb::Database;

use crate::MemAndRedb;

impl MemAndRedb {
    pub async fn new(db_path: impl AsRef<Path>) -> Result<Locked<MemAndRedb>> {
        let db_path = db_path.as_ref();
        fedimint_core::task::block_in_place(|| Self::open_blocking(db_path))
    }

    fn open_blocking(db_path: &Path) -> Result<Locked<MemAndRedb>> {
        std::fs::create_dir_all(
            db_path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("db path must have a base dir"))?,
        )?;
        LockedBuilder::new(db_path)?.with_db(|| {
            let db = Database::create(db_path).context("Failed to create/open redb database")?;
            Self::new_from_redb(db)
        })
    }
}
