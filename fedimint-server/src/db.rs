use std::collections::BTreeSet;

use bitcoin::hex::DisplayHex as _;
use fedimint_core::db::{
    DatabaseTransaction, IDatabaseTransactionOpsCore as _, MODULE_GLOBAL_PREFIX,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
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
