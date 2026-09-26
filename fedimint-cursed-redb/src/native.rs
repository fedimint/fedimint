use std::path::Path;

use fedimint_db_locked::{Locked, LockedBuilder};
use redb::Database;

use crate::{MemAndRedb, MemAndRedbOpenError};

impl MemAndRedb {
    pub async fn new(db_path: impl AsRef<Path>) -> Result<Locked<MemAndRedb>, MemAndRedbOpenError> {
        let db_path = db_path.as_ref();
        fedimint_core::task::block_in_place(|| Self::open_blocking(db_path))
    }

    fn open_blocking(db_path: &Path) -> Result<Locked<MemAndRedb>, MemAndRedbOpenError> {
        std::fs::create_dir_all(db_path.parent().ok_or(MemAndRedbOpenError::NoBaseDir)?)?;
        LockedBuilder::new(db_path)?.with_db(|| {
            let db = match Database::create(db_path) {
                Ok(db) => db,
                Err(redb::DatabaseError::UpgradeRequired(_)) => {
                    Self::migrate_v2_to_v3(db_path)?;
                    Database::create(db_path)
                        .map_err(|e| MemAndRedbOpenError::OpenMigrated(e.into()))?
                }
                Err(e) => return Err(MemAndRedbOpenError::Open(e.into())),
            };
            Ok(Self::new_from_redb(db)?)
        })
    }

    fn migrate_v2_to_v3(db_path: &Path) -> Result<(), MemAndRedbOpenError> {
        tracing::info!("Migrating redb database from v2 to v3 file format");
        let mut old_db =
            redb2::Database::open(db_path).map_err(|e| MemAndRedbOpenError::OpenV2(e.into()))?;
        old_db
            .upgrade()
            .map_err(|e| MemAndRedbOpenError::UpgradeV2(e.into()))?;
        tracing::info!("Successfully migrated redb database to v3 format");
        Ok(())
    }
}
