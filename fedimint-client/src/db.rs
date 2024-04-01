use std::collections::BTreeMap;

use fedimint_core::api::ApiVersionSet;
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::core::{ModuleInstanceId, OperationId};
use fedimint_core::db::{
    migrate_database_version, Database, DatabaseTransaction, DatabaseValue, DatabaseVersion,
    DatabaseVersionKey, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::util::BoxFuture;
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_logging::LOG_DB;
use futures::StreamExt;
use serde::Serialize;
use strum_macros::EnumIter;
use tracing::{info, warn};

use crate::backup::{ClientBackup, Metadata};
use crate::module::recovery::RecoveryProgress;
use crate::oplog::OperationLogEntry;
use crate::sm::executor::{
    ActiveStateKey, ActiveStateKeyBytes, ActiveStateKeyPrefixBytes, InactiveStateKey,
    InactiveStateKeyBytes, InactiveStateKeyPrefixBytes,
};
use crate::sm::{ActiveStateMeta, DynState, InactiveStateMeta};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    EncodedClientSecret = 0x28,
    ClientSecret = 0x29, // Unused
    OperationLog = 0x2c,
    ChronologicalOperationLog = 0x2d,
    CommonApiVersionCache = 0x2e,
    ClientConfig = 0x2f,
    ClientInviteCode = 0x30, // Unused; clean out remnant data before re-using!
    ClientInitState = 0x31,
    ClientMetadata = 0x32,
    ClientLastBackup = 0x33,
    /// Arbitrary data of the applications integrating Fedimint client and
    /// wanting to store some Federation-specific data in Fedimint client
    /// database.
    ///
    /// New users are encouraged to use this single prefix only.
    //
    // TODO: https://github.com/fedimint/fedimint/issues/4444
    //       in the future, we should make all global access to the db private
    //       and only expose a getter returning isolated database.
    UserData = 0xb0,
    /// Prefixes between 0xb1..=0xcf shall all be considered allocated for
    /// historical and future external use
    ExternalReservedStart = 0xb1,
    /// Prefixes between 0xb1..=0xcf shall all be considered allocated for
    /// historical and future external use
    ExternalReservedEnd = 0xcf,
    /// 0xd0.. reserved for Fedimint internal use
    InternalReservedStart = 0xd0,
    /// Per-module instance data
    ModuleGlobalPrefix = 0xff,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable)]
pub struct EncodedClientSecretKey;

#[derive(Debug, Encodable, Decodable)]
pub struct EncodedClientSecretKeyPrefix;

impl_db_record!(
    key = EncodedClientSecretKey,
    value = Vec<u8>,
    db_prefix = DbKeyPrefix::EncodedClientSecret,
);
impl_db_lookup!(
    key = EncodedClientSecretKey,
    query_prefix = EncodedClientSecretKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OperationLogKey {
    pub operation_id: OperationId,
}

impl_db_record!(
    key = OperationLogKey,
    value = OperationLogEntry,
    db_prefix = DbKeyPrefix::OperationLog
);

/// Key used to lookup operation log entries in chronological order
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct ChronologicalOperationLogKey {
    pub creation_time: std::time::SystemTime,
    pub operation_id: OperationId,
}

#[derive(Debug, Encodable)]
pub struct ChronologicalOperationLogKeyPrefix;

impl_db_record!(
    key = ChronologicalOperationLogKey,
    value = (),
    db_prefix = DbKeyPrefix::ChronologicalOperationLog
);

impl_db_lookup!(
    key = ChronologicalOperationLogKey,
    query_prefix = ChronologicalOperationLogKeyPrefix
);

#[derive(Debug, Encodable, Decodable)]
pub struct CachedApiVersionSetKey;

#[derive(Debug, Encodable, Decodable)]
pub struct CachedApiVersionSet(pub ApiVersionSet);

impl_db_record!(
    key = CachedApiVersionSetKey,
    value = CachedApiVersionSet,
    db_prefix = DbKeyPrefix::CommonApiVersionCache
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientConfigKey {
    pub id: FederationId,
}

#[derive(Debug, Encodable)]
pub struct ClientConfigKeyPrefix;

impl_db_record!(
    key = ClientConfigKey,
    value = ClientConfig,
    db_prefix = DbKeyPrefix::ClientConfig
);

impl_db_lookup!(key = ClientConfigKey, query_prefix = ClientConfigKeyPrefix);

/// Client metadata that will be stored/restored on backup&recovery
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientMetadataKey;

#[derive(Debug, Encodable)]
pub struct ClientMetadataPrefix;

impl_db_record!(
    key = ClientMetadataKey,
    value = Metadata,
    db_prefix = DbKeyPrefix::ClientMetadata
);

impl_db_lookup!(key = ClientMetadataKey, query_prefix = ClientMetadataPrefix);

/// Does the client modules need to run recovery before being usable?
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientInitStateKey;

#[derive(Debug, Encodable)]
pub struct ClientInitStatePrefix;

/// Client initialization mode
#[derive(Debug, Encodable, Decodable)]
pub enum InitMode {
    /// Should only be used with freshly generated root secret
    Fresh,
    /// Should be used with root secrets provided by the user to recover a
    /// (even if just possibly) already used secret.
    Recover { snapshot: Option<ClientBackup> },
}

/// Like `InitMode`, but without no longer required data.
///
/// This is distinct from `InitMode` to prevent holding on to `snapshot`
/// forever both for user's privacy and space use. In case user get hacked
/// or phone gets stolen.
#[derive(Debug, Encodable, Decodable)]
pub enum InitModeComplete {
    Fresh,
    Recover,
}

/// The state of the client initialization
#[derive(Debug, Encodable, Decodable)]
pub enum InitState {
    /// Client data initialization might still require some work (e.g. client
    /// recovery)
    Pending(InitMode),
    /// Client initialization was complete
    Complete(InitModeComplete),
}

impl InitState {
    pub fn into_complete(self) -> Self {
        match self {
            InitState::Pending(p) => InitState::Complete(match p {
                InitMode::Fresh => InitModeComplete::Fresh,
                InitMode::Recover { .. } => InitModeComplete::Recover,
            }),
            InitState::Complete(t) => InitState::Complete(t),
        }
    }

    pub fn does_require_recovery(&self) -> Option<Option<ClientBackup>> {
        match self {
            InitState::Pending(p) => match p {
                InitMode::Fresh => None,
                InitMode::Recover { snapshot } => Some(snapshot.clone()),
            },
            InitState::Complete(_) => None,
        }
    }

    pub fn is_pending(&self) -> bool {
        match self {
            InitState::Pending(_) => true,
            InitState::Complete(_) => false,
        }
    }
}

impl_db_record!(
    key = ClientInitStateKey,
    value = InitState,
    db_prefix = DbKeyPrefix::ClientInitState
);

impl_db_lookup!(
    key = ClientInitStateKey,
    query_prefix = ClientInitStatePrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientRecoverySnapshot;

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientRecoverySnapshotPrefix;

impl_db_record!(
    key = ClientRecoverySnapshot,
    value = Option<ClientBackup>,
    db_prefix = DbKeyPrefix::ClientInitState
);

impl_db_lookup!(
    key = ClientRecoverySnapshot,
    query_prefix = ClientRecoverySnapshotPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientModuleRecovery {
    pub module_instance_id: ModuleInstanceId,
}

#[derive(Debug, Encodable)]
pub struct ClientModuleRecoveryPrefix;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct ClientModuleRecoveryState {
    pub progress: RecoveryProgress,
}

impl ClientModuleRecoveryState {
    pub fn is_done(&self) -> bool {
        self.progress.is_done()
    }
}

impl_db_record!(
    key = ClientModuleRecovery,
    value = ClientModuleRecoveryState,
    db_prefix = DbKeyPrefix::ClientInitState,
);

impl_db_lookup!(
    key = ClientModuleRecovery,
    query_prefix = ClientModuleRecoveryPrefix
);

/// Last valid backup the client attempted to make
///
/// Can be used to find previous valid versions of
/// module backup.
#[derive(Debug, Encodable, Decodable)]
pub struct LastBackupKey;

impl_db_record!(
    key = LastBackupKey,
    value = ClientBackup,
    db_prefix = DbKeyPrefix::ClientLastBackup
);

/// `ClientMigrationFn` is a function that modules can implement to "migrate"
/// the database to the next database version.
pub type ClientMigrationFn =
    for<'r, 'tx> fn(
        &'r mut DatabaseTransaction<'tx>,
        ModuleInstanceId,
        Vec<(Vec<u8>, OperationId)>, // active states
        Vec<(Vec<u8>, OperationId)>, // inactive states
        ModuleDecoderRegistry,
    ) -> BoxFuture<'r, anyhow::Result<Option<(Vec<DynState>, Vec<DynState>)>>>;

/// `apply_migrations_client` iterates from the on disk database version for the
/// client module up to `target_db_version` and executes all of the migrations
/// that exist in the migrations map, including state machine migrations.
/// Each migration in the migrations map updates the database to have the
/// correct on-disk data structures that the code is expecting. The entire
/// process is atomic, (i.e migration from 0->1 and 1->2 happen atomically).
/// This function is called before the module is initialized and as long as the
/// correct migrations are supplied in the migrations map, the module
/// will be able to read and write from the database successfully.
pub async fn apply_migrations_client(
    db: &Database,
    kind: String,
    target_db_version: DatabaseVersion,
    migrations: BTreeMap<DatabaseVersion, ClientMigrationFn>,
    module_instance_id: ModuleInstanceId,
    decoders: ModuleDecoderRegistry,
) -> Result<(), anyhow::Error> {
    // TODO(support:v0.3):
    // https://github.com/fedimint/fedimint/issues/3481
    // Somewhere after 0.3 is no longer supported,
    // we should have no need to try to migrate the key, as all
    // clients that ever ran the fixed version, should have it
    // migrated or created in the new place from the start.
    {
        let mut global_dbtx = db.begin_transaction().await;
        migrate_database_version(
            &mut global_dbtx.to_ref_nc(),
            target_db_version,
            Some(module_instance_id),
            kind.clone(),
        )
        .await?;

        global_dbtx.commit_tx_result().await?;
    }

    let mut global_dbtx = db.begin_transaction().await;
    let disk_version = global_dbtx
        .get_value(&DatabaseVersionKey(module_instance_id))
        .await;

    info!(
        ?disk_version,
        ?target_db_version,
        module_instance_id,
        kind,
        "Migrating client module database"
    );

    let db_version = if let Some(disk_version) = disk_version {
        let mut current_db_version = disk_version;

        if current_db_version > target_db_version {
            return Err(anyhow::anyhow!(format!(
                "On disk database version for module {kind} was higher than the code database version."
            )));
        }

        if current_db_version == target_db_version {
            global_dbtx.ignore_uncommitted();
            return Ok(());
        }

        let mut active_states =
            get_active_states(&mut global_dbtx.to_ref_nc(), module_instance_id).await;
        let mut inactive_states =
            get_inactive_states(&mut global_dbtx.to_ref_nc(), module_instance_id).await;

        while current_db_version < target_db_version {
            let new_states = if let Some(migration) = migrations.get(&current_db_version) {
                info!(target: LOG_DB, "Migrating module {kind} current: {current_db_version} target: {target_db_version}");

                migration(
                    &mut global_dbtx
                        .to_ref_with_prefix_module_id(module_instance_id)
                        .into_nc(),
                    module_instance_id,
                    active_states.clone(),
                    inactive_states.clone(),
                    decoders.clone(),
                )
                .await?
            } else {
                warn!("Missing client db migration for version {current_db_version}");
                None
            };

            // If the client migration returned new states, a state machine migration has
            // occurred, and the new states need to be persisted to the database.
            if let Some((new_active_states, new_inactive_states)) = new_states {
                remove_old_and_persist_new_active_states(
                    &mut global_dbtx.to_ref_nc(),
                    new_active_states.clone(),
                    active_states.clone(),
                    module_instance_id,
                )
                .await;
                remove_old_and_persist_new_inactive_states(
                    &mut global_dbtx.to_ref_nc(),
                    new_inactive_states.clone(),
                    inactive_states.clone(),
                    module_instance_id,
                )
                .await;

                // the new states become the old states for the next migration
                active_states = new_active_states
                    .into_iter()
                    .map(|state| (state.to_bytes(), state.operation_id()))
                    .collect::<Vec<_>>();
                inactive_states = new_inactive_states
                    .into_iter()
                    .map(|state| (state.to_bytes(), state.operation_id()))
                    .collect::<Vec<_>>();
            }

            current_db_version.increment();
            global_dbtx
                .insert_entry(&DatabaseVersionKey(module_instance_id), &current_db_version)
                .await;
        }

        current_db_version
    } else {
        target_db_version
    };

    global_dbtx.commit_tx_result().await?;
    info!(target: LOG_DB, "{} module db version: {} migration complete", kind, db_version);
    Ok(())
}

/// Reads all active states from the database and returns `Vec<DynState>`.
/// TODO: It is unfortunate that we can't read states by the module's instance
/// id so we are forced to return all active states. Once we do a db migration
/// to add `module_instance_id` to `ActiveStateKey`, this can be improved to
/// only read the module's relevant states.
pub async fn get_active_states(
    dbtx: &mut DatabaseTransaction<'_>,
    module_instance_id: ModuleInstanceId,
) -> Vec<(Vec<u8>, OperationId)> {
    dbtx.find_by_prefix(&ActiveStateKeyPrefixBytes)
        .await
        .filter_map(|(state, _)| async move {
            if module_instance_id == state.module_instance_id {
                Some((state.state, state.operation_id))
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .await
}

/// Reads all inactive states from the database and returns `Vec<DynState>`.
/// TODO: It is unfortunate that we can't read states by the module's instance
/// id so we are forced to return all inactive states. Once we do a db migration
/// to add `module_instance_id` to `InactiveStateKey`, this can be improved to
/// only read the module's relevant states.
pub async fn get_inactive_states(
    dbtx: &mut DatabaseTransaction<'_>,
    module_instance_id: ModuleInstanceId,
) -> Vec<(Vec<u8>, OperationId)> {
    dbtx.find_by_prefix(&InactiveStateKeyPrefixBytes)
        .await
        .filter_map(|(state, _)| async move {
            if module_instance_id == state.module_instance_id {
                Some((state.state, state.operation_id))
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .await
}

/// Persists new active states by first removing all current active states, and
/// re-writing with the new set of active states. `new_active_states` is
/// expected to contain all active states, not just the newly created states.
pub async fn remove_old_and_persist_new_active_states(
    dbtx: &mut DatabaseTransaction<'_>,
    new_active_states: Vec<DynState>,
    states_to_remove: Vec<(Vec<u8>, OperationId)>,
    module_instance_id: ModuleInstanceId,
) {
    // Remove all existing active states
    for (bytes, operation_id) in states_to_remove {
        dbtx.remove_entry(&ActiveStateKeyBytes {
            operation_id,
            module_instance_id,
            state: bytes,
        })
        .await
        .expect("Did not delete anything");
    }

    let new_active_states = new_active_states
        .into_iter()
        .map(|state| {
            (
                ActiveStateKey::from_state(state),
                ActiveStateMeta::default(),
            )
        })
        .collect::<Vec<_>>();

    // Insert new "migrated" active states
    for (state, active_state) in new_active_states {
        dbtx.insert_new_entry(&state, &active_state).await;
    }
}

/// Persists new inactive states by first removing all current inactive states,
/// and re-writing with the new set of inactive states. `new_inactive_states` is
/// expected to contain all inactive states, not just the newly created states.
pub async fn remove_old_and_persist_new_inactive_states(
    dbtx: &mut DatabaseTransaction<'_>,
    new_inactive_states: Vec<DynState>,
    states_to_remove: Vec<(Vec<u8>, OperationId)>,
    module_instance_id: ModuleInstanceId,
) {
    // Remove all existing active states
    for (bytes, operation_id) in states_to_remove {
        dbtx.remove_entry(&InactiveStateKeyBytes {
            operation_id,
            module_instance_id,
            state: bytes,
        })
        .await
        .expect("Did not delete anything");
    }

    let new_inactive_states = new_inactive_states
        .into_iter()
        .map(|state| {
            (
                InactiveStateKey::from_state(state),
                InactiveStateMeta {
                    created_at: fedimint_core::time::now(),
                    exited_at: fedimint_core::time::now(),
                },
            )
        })
        .collect::<Vec<_>>();

    // Insert new "migrated" inactive states
    for (state, inactive_state) in new_inactive_states {
        dbtx.insert_new_entry(&state, &inactive_state).await;
    }
}
