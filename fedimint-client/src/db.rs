use fedimint_core::api::{ApiVersionSet, InviteCode};
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::core::{ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use serde::Serialize;
use strum_macros::EnumIter;

use crate::backup::{ClientBackup, Metadata};
use crate::module::recovery::RecoveryProgress;
use crate::oplog::OperationLogEntry;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    EncodedClientSecret = 0x28,
    ClientSecret = 0x29, // Unused
    OperationLog = 0x2c,
    ChronologicalOperationLog = 0x2d,
    CommonApiVersionCache = 0x2e,
    ClientConfig = 0x2f,
    ClientInviteCode = 0x30,
    ClientInitState = 0x31,
    ClientMetadata = 0x32,
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

#[derive(Debug, Encodable, Decodable)]
pub struct ClientInviteCodeKey;

#[derive(Debug, Encodable)]
pub struct ClientInviteCodeKeyPrefix;

impl_db_record!(
    key = ClientInviteCodeKey,
    value = InviteCode,
    db_prefix = DbKeyPrefix::ClientInviteCode
);

impl_db_lookup!(
    key = ClientInviteCodeKey,
    query_prefix = ClientInviteCodeKeyPrefix
);

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
