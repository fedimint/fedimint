use std::collections::BTreeSet;

use bitcoin::hex::DisplayHex as _;
use fedimint_core::db::{
    DatabaseTransaction, IDatabaseTransactionOpsCore as _, MODULE_GLOBAL_PREFIX,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use futures::StreamExt as _;
use strum::{EnumIter, IntoEnumIterator as _};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    AcceptedItem = 0x01,
    AcceptedTransaction = 0x02,
    SignedSessionOutcome = 0x04,
    AlephUnits = 0x05,
    // TODO: do we want to split the server DB into consensus/non-consensus?
    ApiAnnouncements = 0x06,
    ServerInfo = 0x07,
    GuardianMetadata = 0x08,
    InviteId = 0x09,
    InviteUserCount = 0x0a,

    DatabaseVersion = fedimint_core::db::DbKeyPrefix::DatabaseVersion as u8,
    ClientBackup = fedimint_core::db::DbKeyPrefix::ClientBackup as u8,
    Module = MODULE_GLOBAL_PREFIX,
}

pub(crate) async fn verify_server_db_integrity_dbtx(dbtx: &mut DatabaseTransaction<'_>) {
    let prefixes: BTreeSet<u8> = DbKeyPrefix::iter().map(|prefix| prefix as u8).collect();

    let mut records = dbtx.raw_find_by_prefix(&[]).await.expect("DB fail");
    while let Some((k, v)) = records.next().await {
        // We don't want to waste time checking these
        if k[0] == DbKeyPrefix::Module as u8 {
            break;
        }

        assert!(
            prefixes.contains(&k[0]),
            "Unexpected server db record found: {}: {}",
            k.as_hex(),
            v.as_hex()
        );
    }
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ServerInfoKey;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ServerInfo {
    /// The initial version that set up the consensus
    pub init_version: String,
    /// The last version that passed db migration checks
    pub last_version: String,
}

impl_db_record!(
    key = ServerInfoKey,
    value = ServerInfo,
    db_prefix = DbKeyPrefix::ServerInfo,
    notify_on_modify = false,
);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct InviteIdKey(pub [u8; 16]);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct InviteIdKeyPrefix;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct InviteIdMeta {
    /// Unix timestamp in seconds after which the invite code is expired
    pub expires_at: u64,
    /// Maximum number of users that may join via this invite code
    pub user_limit: u64,
}

impl_db_record!(
    key = InviteIdKey,
    value = InviteIdMeta,
    db_prefix = DbKeyPrefix::InviteId,
    notify_on_modify = false,
);

impl_db_lookup!(key = InviteIdKey, query_prefix = InviteIdKeyPrefix);

/// Number of users that have joined via the invite code with this invite id so
/// far; a missing entry means zero
#[derive(Clone, Debug, Encodable, Decodable)]
pub struct InviteUserCountKey(pub [u8; 16]);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct InviteUserCountKeyPrefix;

impl_db_record!(
    key = InviteUserCountKey,
    value = u64,
    db_prefix = DbKeyPrefix::InviteUserCount,
    notify_on_modify = false,
);

impl_db_lookup!(
    key = InviteUserCountKey,
    query_prefix = InviteUserCountKeyPrefix
);
