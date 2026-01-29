//! Database keys for fedimint-cli
//!
//! These keys use the UserData prefix (0xb0) as recommended for external/CLI
//! data that shouldn't be in the core client database schema.

use fedimint_client::db::DbKeyPrefix as ClientDbKeyPrefix;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, impl_db_record};
use serde::{Deserialize, Serialize};

/// Sub-prefix for CLI-specific data under UserData (0xb0)
const CLI_USER_DATA_SUB_PREFIX: u8 = 0x00;

/// Get a CLI-specific database with the UserData prefix already applied
pub fn cli_database(db: &Database) -> Database {
    db.with_prefix(vec![
        ClientDbKeyPrefix::UserData as u8,
        CLI_USER_DATA_SUB_PREFIX,
    ])
}

/// Key prefix enum for CLI database keys
#[repr(u8)]
#[derive(Clone, Debug)]
pub enum CliDbKeyPrefix {
    AdminCreds = 0x00,
}

impl std::fmt::Display for CliDbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                CliDbKeyPrefix::AdminCreds => "AdminCreds",
            }
        )
    }
}

/// Key for storing admin credentials
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct AdminCredsKey;

/// The stored admin credentials value
#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize)]
pub struct StoredAdminCreds {
    /// Guardian's own peer_id
    pub peer_id: PeerId,
    /// Authentication password (stored as String, will be wrapped in ApiAuth
    /// when used)
    pub auth: String,
}

impl_db_record!(
    key = AdminCredsKey,
    value = StoredAdminCreds,
    db_prefix = CliDbKeyPrefix::AdminCreds,
);

/// Load stored admin credentials from the CLI database
pub async fn load_admin_creds(db: &Database) -> Option<StoredAdminCreds> {
    let cli_db = cli_database(db);
    cli_db
        .begin_transaction_nc()
        .await
        .get_value(&AdminCredsKey)
        .await
}

/// Store admin credentials in the CLI database
pub async fn store_admin_creds(db: &Database, creds: &StoredAdminCreds) {
    let cli_db = cli_database(db);
    let mut dbtx = cli_db.begin_transaction().await;
    dbtx.insert_entry(&AdminCredsKey, creds).await;
    dbtx.commit_tx().await;
}
