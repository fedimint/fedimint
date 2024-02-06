use std::fs::read_dir;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::{env, fs, io};

use anyhow::{bail, format_err, Context};
use fedimint_core::db::{apply_migrations, apply_migrations_server, Database};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::DynCommonModuleInit;
use fedimint_rocksdb::RocksDb;
use fedimint_server::db::{get_global_database_migrations, GLOBAL_DATABASE_VERSION};
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

/// Opens the backup database in the `snapshot_dir`. If the `is_isolated` flag
/// is set, the database will be opened as an isolated database with
/// `TEST_MODULE_INSTANCE_ID` as the prefix.
async fn open_snapshot_db(
    decoders: ModuleDecoderRegistry,
    snapshot_dir: PathBuf,
    is_isolated: bool,
) -> anyhow::Result<Database> {
    if is_isolated {
        Ok(Database::new(
            RocksDb::open(&snapshot_dir)
                .with_context(|| format!("Preparing snapshot in {}", snapshot_dir.display()))?,
            decoders,
        )
        .with_prefix_module_id(TEST_MODULE_INSTANCE_ID))
    } else {
        Ok(Database::new(
            RocksDb::open(&snapshot_dir)
                .with_context(|| format!("Preparing snapshot in {}", snapshot_dir.display()))?,
            decoders,
        ))
    }
}

/// Creates a backup database in the `snapshot_dir` according to the
/// `FM_PREPARE_DB_MIGRATION_SNAPSHOTS`, since we do not want to re-create a
/// backup database every time we run the tests.
async fn create_snapshot<'a, F>(
    snapshot_dir: PathBuf,
    decoders: ModuleDecoderRegistry,
    is_isolated: bool,
    prepare_fn: F,
) -> anyhow::Result<()>
where
    F: Fn(Database) -> BoxFuture<'a, ()>,
{
    const ENV_VAR_NAME: &str = "FM_PREPARE_DB_MIGRATION_SNAPSHOTS";
    match (
        std::env::var_os(ENV_VAR_NAME)
            .map(|s| s.to_string_lossy().into_owned())
            .as_deref(),
        snapshot_dir.exists(),
    ) {
        (Some("force"), true) => {
            tokio::fs::remove_dir_all(&snapshot_dir).await?;
            let db = open_snapshot_db(decoders, snapshot_dir, is_isolated).await?;
            prepare_fn(db).await;
        }
        (Some(_), true) => {
            bail!("{ENV_VAR_NAME} set, but {} already exists already exists. Set to 'force' to overwrite.", snapshot_dir.display());
        }
        (Some(_), false) => {
            debug!(dir = %snapshot_dir.display(), "Snapshot dir does not exist. Creating.");
            let db = open_snapshot_db(decoders, snapshot_dir, is_isolated).await?;
            prepare_fn(db).await;
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

/// Creates the database backup for `fedimint-server`
/// to `db/migrations`. Then this function will execute the provided
/// `prepare_fn` which is expected to populate the database with the appropriate
/// data for testing a migration. If the snapshot directory already exists,
/// this function will do nothing.
pub async fn snapshot_db_migrations_server<'a, F>(
    prepare_fn: F,
    decoders: ModuleDecoderRegistry,
) -> anyhow::Result<()>
where
    F: Fn(Database) -> BoxFuture<'a, ()>,
{
    let project_root = get_project_root().unwrap();
    let snapshot_dir = project_root.join("db/migrations").join("fedimint-server");
    create_snapshot(snapshot_dir, decoders, false, prepare_fn).await
}

/// Creates the database backup directory by appending the `snapshot_name`
/// to `db/migrations`. Then this function will execute the provided
/// `prepare_fn` which is expected to populate the database with the appropriate
/// data for testing a migration. If the snapshot directory already exists,
/// this function will do nothing.
pub async fn snapshot_db_migrations<'a, F>(
    module: DynCommonModuleInit,
    snapshot_name: &str,
    prepare_fn: F,
) -> anyhow::Result<()>
where
    F: Fn(Database) -> BoxFuture<'a, ()>,
{
    let project_root = get_project_root().unwrap();
    let snapshot_dir = project_root.join("db/migrations").join(snapshot_name);

    let decoders = ModuleDecoderRegistry::from_iter([(
        TEST_MODULE_INSTANCE_ID,
        module.module_kind(),
        module.decoder(),
    )]);
    create_snapshot(snapshot_dir, decoders, true, prepare_fn).await
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
pub const TEST_MODULE_INSTANCE_ID: u16 = 0;

/// Retrieves a temporary database from the database backup directory.
/// The first folder that starts with `db_prefix` will return as a temporary
/// database.
async fn get_temp_database(
    db_prefix: &str,
    decoders: ModuleDecoderRegistry,
) -> anyhow::Result<Database> {
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
                        .with_context(|| {
                            format!("Opening temp db for {name}. Copying to {temp_path}")
                        })?;
                return Ok(temp_db);
            }
        }
    }

    Err(anyhow::anyhow!(
        "No database with prefix {db_prefix} in backup directory"
    ))
}

/// Validates the `fedimint-server` database migrations. `decoders` need to be
/// passed in as an argument since `fedimint-server` is module agnostic. First
/// applies all defined migrations to the database then executes the `validate``
/// function which should confirm the database migrations were successful.
pub async fn validate_migrations_server<F, Fut>(
    validate: F,
    decoders: ModuleDecoderRegistry,
) -> anyhow::Result<()>
where
    F: Fn(Database) -> Fut,
    Fut: futures::Future<Output = anyhow::Result<()>>,
{
    let db = get_temp_database("fedimint-server", decoders).await?;
    apply_migrations_server(
        &db,
        "fedimint-server".to_string(),
        GLOBAL_DATABASE_VERSION,
        get_global_database_migrations(),
    )
    .await
    .context("Error applying migrations to temp database")?;

    validate(db)
        .await
        .with_context(|| "Validating fedimint-server".to_string())?;
    Ok(())
}

/// Validates the database migrations for each module. First applies all
/// database migrations to the module, then calls the `validate` which should
/// confirm the database migrations were successful.
pub async fn validate_migrations_module<F, Fut>(
    module: DynCommonModuleInit,
    db_prefix: &str,
    validate: F,
) -> anyhow::Result<()>
where
    F: Fn(Database) -> Fut,
    Fut: futures::Future<Output = anyhow::Result<()>>,
{
    let decoders = ModuleDecoderRegistry::from_iter([(
        TEST_MODULE_INSTANCE_ID,
        module.module_kind(),
        module.decoder(),
    )]);
    let db = get_temp_database(db_prefix, decoders).await?;
    apply_migrations(
        &db,
        module.module_kind().to_string(),
        module.database_version(),
        module.get_database_migrations(),
        Some(TEST_MODULE_INSTANCE_ID),
    )
    .await
    .context("Error applying migrations to temp database")?;

    let module_db = db.with_prefix_module_id(TEST_MODULE_INSTANCE_ID);
    validate(module_db)
        .await
        .with_context(|| format!("Validating {db_prefix}"))?;

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
