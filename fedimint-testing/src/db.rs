use std::fs::read_dir;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::{env, fs, io};

use anyhow::{bail, format_err, Context};
use fedimint_core::db::{Database, DatabaseTransaction};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_rocksdb::RocksDb;
use futures::future::BoxFuture;
use rand::rngs::OsRng;
use rand::RngCore;
use tracing::debug;

/// Get the project root (relative to closest Cargo.lock file)
/// ```rust
/// match fedimint_testing::db::get_project_root() {
///     Ok(p) => println!("Current project root is {:?}", p),
///     Err(e) => println!("Error obtaining project root {:?}", e),
/// };
/// ```
pub fn get_project_root() -> io::Result<PathBuf> {
    let path = env::current_dir()?;
    let path_ancestors = path.as_path().ancestors();

    for p in path_ancestors {
        let has_cargo = read_dir(p)?.any(|p| p.unwrap().file_name() == *"Cargo.lock");
        if has_cargo {
            return Ok(PathBuf::from(p));
        }
    }
    Err(io::Error::new(
        ErrorKind::NotFound,
        "Ran out of places to find Cargo.toml",
    ))
}

/// Creates the database backup directory by appending the `snapshot_name`
/// to `db/migrations`. Then this function will execute the provided
/// `prepare_fn` which is expected to populate the database with the appropriate
/// data for testing a migration. If the snapshot directory already exists,
/// this function will do nothing.
pub async fn prepare_db_migration_snapshot<F>(
    snapshot_name: &str,
    prepare_fn: F,
    decoders: ModuleDecoderRegistry,
) -> anyhow::Result<()>
where
    F: for<'a> Fn(DatabaseTransaction<'a>) -> BoxFuture<'a, ()>,
{
    let project_root = get_project_root().unwrap();
    let snapshot_dir = project_root.join("db/migrations").join(snapshot_name);

    async fn prepare<F>(
        snapshot_dir: PathBuf,
        prepare_fn: F,
        decoders: ModuleDecoderRegistry,
    ) -> anyhow::Result<()>
    where
        F: for<'a> Fn(DatabaseTransaction<'a>) -> BoxFuture<'a, ()>,
    {
        let db = Database::new(
            RocksDb::open(&snapshot_dir)
                .with_context(|| format!("Preparing snapshot in {}", snapshot_dir.display()))?,
            decoders,
        );
        let mut dbtx = db.begin_transaction().await;
        prepare_fn(dbtx.to_ref_nc()).await;
        dbtx.commit_tx().await;
        Ok(())
    }

    const ENV_VAR_NAME: &str = "FM_PREPARE_DB_MIGRATION_SNAPSHOTS";
    match (
        std::env::var_os(ENV_VAR_NAME)
            .map(|s| s.to_string_lossy().into_owned())
            .as_deref(),
        snapshot_dir.exists(),
    ) {
        (Some("force"), true) => {
            tokio::fs::remove_dir_all(&snapshot_dir).await?;
            prepare(snapshot_dir, prepare_fn, decoders).await?;
        }
        (Some(_), true) => {
            bail!("{ENV_VAR_NAME} set, but {} already exists already exists. Set to 'force' to overwrite.", snapshot_dir.display());
        }
        (Some(_), false) => {
            debug!(dir = %snapshot_dir.display(), "Snapshot dir does not exist. Creating.");
            prepare(snapshot_dir, prepare_fn, decoders).await?;
        }
        (None, true) => {
            debug!(dir = %snapshot_dir.display(), "Snapshot dir already exist. Nothing to do.");
        }
        (None, false) => {
            bail!(
                "{ENV_VAR_NAME} not set, but {} doest not exist.",
                snapshot_dir.display()
            );
        }
    }

    Ok(())
}

pub const STRING_64: &str = "0123456789012345678901234567890101234567890123456789012345678901";
pub const BYTE_8: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
pub const BYTE_20: [u8; 20] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
pub const BYTE_32: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
];
pub const BYTE_33: [u8; 33] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
    2,
];

/// Iterates over all of the databases supplied in the database backup
/// directory. First, a temporary database will be created and the contents will
/// be populated from the database backup directory. Next, this function will
/// execute the provided `validate` closure. The `validate` closure is expected
/// to do any validation necessary on the temporary database, such as applying
/// the appropriate database migrations and then reading all of the data to
/// verify the migrations were successful.
pub async fn validate_migrations<F, Fut>(
    db_prefix: &str,
    validate: F,
    decoders: ModuleDecoderRegistry,
) -> anyhow::Result<()>
where
    F: Fn(Database) -> Fut,
    Fut: futures::Future<Output = anyhow::Result<()>>,
{
    let snapshot_dirs = get_project_root().unwrap().join("db/migrations");
    if snapshot_dirs.exists() {
        for file in fs::read_dir(snapshot_dirs)?.flatten() {
            let name = file
                .file_name()
                .into_string()
                .map_err(|_e| format_err!("Invalid path name"))?;
            if name.starts_with(db_prefix) {
                let temp_path = format!("{}-{}", name.as_str(), OsRng.next_u64());
                let temp_db =
                    open_temp_db_and_copy(temp_path.clone(), &file.path(), decoders.clone())
                        .with_context(|| format!("Validating {name}, copied to {temp_path}"))?;
                validate(temp_db)
                    .await
                    .with_context(|| format!("Validating {name}, copied to {temp_path}"))?;
            }
        }
    }
    Ok(())
}

/// Open a temporary database located at `temp_path` and copy the contents from
/// the folder `src_dir` to the temporary database's path.
fn open_temp_db_and_copy(
    temp_path: String,
    src_dir: &Path,
    decoders: ModuleDecoderRegistry,
) -> anyhow::Result<Database> {
    // First copy the contents from src_dir to the path where the database will be
    // opened
    let path = tempfile::Builder::new()
        .prefix(temp_path.as_str())
        .tempdir()?;
    copy_directory(src_dir, path.path())
        .context("Error copying database to temporary directory")?;

    Ok(Database::new(RocksDb::open(path)?, decoders))
}

/// Helper function that recursively copies all of the contents from
/// `atomic_broadcast` to `dst`.
pub fn copy_directory(src: &Path, dst: &Path) -> io::Result<()> {
    // Create the destination directory if it doesn't exist
    fs::create_dir_all(dst)?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            copy_directory(&path, &dst.join(entry.file_name()))?;
        } else {
            let dst_path = dst.join(entry.file_name());
            fs::copy(&path, &dst_path)?;
        }
    }

    Ok(())
}
