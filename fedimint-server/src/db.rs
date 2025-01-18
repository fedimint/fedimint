use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;

use crate::consensus::db::DbKeyPrefix;

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
