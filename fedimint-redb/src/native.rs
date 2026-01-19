use std::path::Path;

use anyhow::{Context as _, Result};
use fedimint_db_locked::{Locked, LockedBuilder};
use redb::Database;

use crate::RedbDatabase;

impl RedbDatabase {
    pub async fn new(db_path: impl AsRef<Path>) -> Result<Locked<RedbDatabase>> {
        let db_path = db_path.as_ref();
        fedimint_core::task::block_in_place(|| Self::open_blocking(db_path))
    }

    fn open_blocking(db_path: &Path) -> Result<Locked<RedbDatabase>> {
        std::fs::create_dir_all(
            db_path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("db path must have a parent directory"))?,
        )?;
        LockedBuilder::new(db_path)?.with_db(|| {
            let db = Database::create(db_path).context("Failed to create/open redb database")?;
            Self::from_redb(db).map_err(|e| anyhow::Error::msg(e.to_string()))
        })
    }
}
