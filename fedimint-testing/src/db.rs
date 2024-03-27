use std::collections::BTreeMap;
use std::fs::read_dir;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::{env, fs, io};

use anyhow::{bail, format_err, Context};
use fedimint_client::db::apply_migrations_client;
use fedimint_client::module::init::DynClientModuleInit;
use fedimint_client::module::ClientModule;
use fedimint_client::sm::{
    ActiveStateKeyBytes, ActiveStateKeyPrefix, ActiveStateMeta, InactiveStateKeyBytes,
    InactiveStateKeyPrefix, InactiveStateMeta,
};
use fedimint_core::core::OperationId;
use fedimint_core::db::{
    apply_migrations, apply_migrations_server, Database, DatabaseVersion,
    IDatabaseTransactionOpsCoreTyped, ServerMigrationFn,
};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{CommonModuleInit, DynServerModuleInit};
use fedimint_logging::LOG_TEST;
use fedimint_rocksdb::RocksDb;
use futures::future::BoxFuture;
use futures::{FutureExt, StreamExt};
use rand::rngs::OsRng;
use rand::RngCore;
use tempfile::TempDir;
use tracing::{debug, trace};

use crate::envs::FM_PREPARE_DB_MIGRATION_SNAPSHOTS_ENV;

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
    F: FnOnce(Database) -> BoxFuture<'a, ()>,
{
    match (
        std::env::var_os(FM_PREPARE_DB_MIGRATION_SNAPSHOTS_ENV)
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
            bail!("{FM_PREPARE_DB_MIGRATION_SNAPSHOTS_ENV} set, but {} already exists already exists. Set to 'force' to overwrite.", snapshot_dir.display());
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
                "{FM_PREPARE_DB_MIGRATION_SNAPSHOTS_ENV} not set, but {} doest not exist.",
                snapshot_dir.display()
            );
        }
    }
    Ok(())
}

/// Creates the database backup for `snapshot_name`
/// to `db/migrations`. Then this function will execute the provided
/// `prepare_fn` which is expected to populate the database with the appropriate
/// data for testing a migration. If the snapshot directory already exists,
/// this function will do nothing.
pub async fn snapshot_db_migrations_with_decoders<'a, F>(
    snapshot_name: &str,
    prepare_fn: F,
    decoders: ModuleDecoderRegistry,
) -> anyhow::Result<()>
where
    F: Fn(Database) -> BoxFuture<'a, ()>,
{
    let project_root = get_project_root().unwrap();
    let snapshot_dir = project_root.join("db/migrations").join(snapshot_name);
    create_snapshot(snapshot_dir, decoders, false, prepare_fn).await
}

/// Creates the database backup directory for a server module by appending the
/// `snapshot_name` to `db/migrations`. Then this function will execute the
/// provided `prepare_fn` which is expected to populate the database with the
/// appropriate data for testing a migration.
pub async fn snapshot_db_migrations<'a, F, I>(
    snapshot_name: &str,
    prepare_fn: F,
) -> anyhow::Result<()>
where
    F: Fn(Database) -> BoxFuture<'a, ()>,
    I: CommonModuleInit,
{
    let project_root = get_project_root().unwrap();
    let snapshot_dir = project_root.join("db/migrations").join(snapshot_name);

    let decoders =
        ModuleDecoderRegistry::from_iter([(TEST_MODULE_INSTANCE_ID, I::KIND, I::decoder())]);
    create_snapshot(snapshot_dir, decoders, true, prepare_fn).await
}

/// Create the database backup directory for a client module.
/// Two prepare functions are taken as parameters. `data_prepare` is expected to
/// create any data that the client module uses and is stored in the isolated
/// namespace. `state_machine_prepare` creates client state machine data that
/// can be used for testing state machine migrations. This is created in the
/// global namespace.
pub async fn snapshot_db_migrations_client<'a, F, S, I>(
    snapshot_name: &str,
    data_prepare: F,
    state_machine_prepare: S,
) -> anyhow::Result<()>
where
    F: Fn(Database) -> BoxFuture<'a, ()> + Send + Sync,
    S: Fn() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) + Send + Sync,
    I: CommonModuleInit,
{
    let project_root = get_project_root().unwrap();
    let snapshot_dir = project_root.join("db/migrations").join(snapshot_name);

    let decoders =
        ModuleDecoderRegistry::from_iter([(TEST_MODULE_INSTANCE_ID, I::KIND, I::decoder())]);

    let snapshot_fn = |db: Database| {
        async move {
            let isolated_db = db.with_prefix_module_id(TEST_MODULE_INSTANCE_ID);
            data_prepare(isolated_db).await;

            let (active_states, inactive_states) = state_machine_prepare();
            let mut global_dbtx = db.begin_transaction().await;

            for state in active_states {
                global_dbtx
                    .insert_new_entry(
                        &ActiveStateKeyBytes {
                            operation_id: OperationId::new_random(),
                            module_instance_id: TEST_MODULE_INSTANCE_ID,
                            state,
                        },
                        &ActiveStateMeta {
                            created_at: fedimint_core::time::now(),
                        },
                    )
                    .await;
            }

            for state in inactive_states {
                global_dbtx
                    .insert_new_entry(
                        &InactiveStateKeyBytes {
                            operation_id: OperationId::new_random(),
                            module_instance_id: TEST_MODULE_INSTANCE_ID,
                            state,
                        },
                        &InactiveStateMeta {
                            created_at: fedimint_core::time::now(),
                            exited_at: fedimint_core::time::now(),
                        },
                    )
                    .await;
            }

            global_dbtx.commit_tx().await;
        }
        .boxed()
    };

    create_snapshot(snapshot_dir, decoders, false, snapshot_fn).await
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
) -> anyhow::Result<(Database, TempDir)> {
    let snapshot_dirs = get_project_root().unwrap().join("db/migrations");
    if snapshot_dirs.exists() {
        for file in fs::read_dir(&snapshot_dirs)
            .with_context(|| format!("Reading dir content: {}", snapshot_dirs.display()))?
            .flatten()
        {
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

/// Validates the database migrations. `decoders` need to be
/// passed in as an argument since this is module agnostic. First
/// applies all defined migrations to the database then executes the `validate``
/// function which should confirm the database migrations were successful.
pub async fn validate_migrations_global<F, Fut>(
    validate: F,
    db_prefix: &str,
    target_db_version: DatabaseVersion,
    migrations: BTreeMap<DatabaseVersion, ServerMigrationFn>,
    decoders: ModuleDecoderRegistry,
) -> anyhow::Result<()>
where
    F: Fn(Database) -> Fut,
    Fut: futures::Future<Output = anyhow::Result<()>>,
{
    let (db, _tmp_dir) = get_temp_database(db_prefix, decoders).await?;
    apply_migrations_server(&db, db_prefix.to_string(), target_db_version, migrations)
        .await
        .context("Error applying migrations to temp database")?;

    validate(db)
        .await
        .with_context(|| format!("Validating {db_prefix}"))?;
    Ok(())
}

/// Validates the database migrations for a server module. First applies all
/// database migrations to the module, then calls the `validate` which should
/// confirm the database migrations were successful.
pub async fn validate_migrations_server<F, Fut>(
    module: DynServerModuleInit,
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
    let (db, _tmp_dir) = get_temp_database(db_prefix, decoders).await?;
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

/// Validates the database migrations for a client module. First applies all
/// database migrations to the module, including the state machine migrations.
/// Then calls the `validate` function, including the new `active_states` and
/// `inactive_states`, and is expected to confirm the database migrations were
/// successful.
pub async fn validate_migrations_client<F, Fut, T>(
    module: DynClientModuleInit,
    db_prefix: &str,
    validate: F,
) -> anyhow::Result<()>
where
    F: Fn(Database, Vec<T::States>, Vec<T::States>) -> Fut,
    Fut: futures::Future<Output = anyhow::Result<()>>,
    T: ClientModule,
{
    let decoders = ModuleDecoderRegistry::from_iter([(
        TEST_MODULE_INSTANCE_ID,
        module.as_common().module_kind(),
        T::decoder(),
    )]);
    let (db, _tmp_dir) = get_temp_database(db_prefix, decoders.clone()).await?;
    apply_migrations_client(
        &db,
        module.as_common().module_kind().to_string(),
        module.database_version(),
        module.get_database_migrations(),
        TEST_MODULE_INSTANCE_ID,
        decoders,
    )
    .await
    .context("Error applying migrations to temp database")?;

    let mut global_dbtx = db.begin_transaction_nc().await;
    let active_states = global_dbtx
        .find_by_prefix(&ActiveStateKeyPrefix)
        .await
        .filter_map(|(state, _)| async move {
            state.state.as_any().downcast_ref::<T::States>().cloned()
        })
        .collect::<Vec<_>>()
        .await;

    let inactive_states = global_dbtx
        .find_by_prefix(&InactiveStateKeyPrefix)
        .await
        .filter_map(|(state, _)| async move {
            state.state.as_any().downcast_ref::<T::States>().cloned()
        })
        .collect::<Vec<_>>()
        .await;

    let module_db = db.with_prefix_module_id(TEST_MODULE_INSTANCE_ID);
    validate(module_db, active_states, inactive_states)
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
) -> anyhow::Result<(Database, TempDir)> {
    // First copy the contents from src_dir to the path where the database will be
    // opened
    let tmp_dir = tempfile::Builder::new()
        .prefix(temp_path.as_str())
        .tempdir()?;
    copy_directory(src_dir, tmp_dir.path())
        .context("Error copying database to temporary directory")?;

    Ok((Database::new(RocksDb::open(&tmp_dir)?, decoders), tmp_dir))
}

/// Helper function that recursively copies all of the contents from
/// `atomic_broadcast` to `dst`.
pub fn copy_directory(src: &Path, dst: &Path) -> io::Result<()> {
    trace!(target: LOG_TEST, src = %src.display(), dst = %dst.display(), "Copy dir");

    // Create the destination directory if it doesn't exist
    fs::create_dir_all(dst)?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            copy_directory(&path, &dst.join(entry.file_name()))?;
        } else {
            let dst_path = dst.join(entry.file_name());
            trace!(target: LOG_TEST, src = %path.display(), dst = %dst_path.display(), "Copy file");
            fs::copy(&path, &dst_path)?;
        }
    }

    Ok(())
}
