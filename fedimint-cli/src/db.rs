//! Database keys for fedimint-cli
//!
//! These keys use the UserData prefix (0xb0) as recommended for external/CLI
//! data that shouldn't be in the core client database schema.

use fedimint_client::db::DbKeyPrefix;
use fedimint_core::PeerId;
use fedimint_core::db::IDatabaseTransactionOpsCore;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleRegistry;
use serde::{Deserialize, Serialize};

/// Sub-prefix for CLI-specific data under UserData (0xb0)
/// Using 0x00 as the first sub-prefix for admin credentials
const CLI_ADMIN_CREDS_SUB_PREFIX: u8 = 0x00;

/// The stored admin credentials value
#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize)]
pub struct StoredAdminCreds {
    /// Guardian's own peer_id
    pub peer_id: PeerId,
    /// Authentication password (stored as String, will be wrapped in ApiAuth
    /// when used)
    pub auth: String,
}

/// Get the raw key bytes for admin credentials
fn admin_creds_key() -> Vec<u8> {
    vec![DbKeyPrefix::UserData as u8, CLI_ADMIN_CREDS_SUB_PREFIX]
}

/// Load stored admin credentials from the database
pub async fn load_admin_creds(
    dbtx: &mut (impl IDatabaseTransactionOpsCore + Send),
) -> Option<StoredAdminCreds> {
    let key = admin_creds_key();
    dbtx.raw_get_bytes(&key)
        .await
        .expect("DB read should not fail")
        .and_then(|bytes| {
            StoredAdminCreds::consensus_decode_whole(&bytes, &ModuleRegistry::default()).ok()
        })
}

/// Store admin credentials in the database
pub async fn store_admin_creds(
    dbtx: &mut (impl IDatabaseTransactionOpsCore + Send),
    creds: &StoredAdminCreds,
) {
    let key = admin_creds_key();
    let value = creds.consensus_encode_to_vec();
    dbtx.raw_insert_bytes(&key, &value)
        .await
        .expect("DB write should not fail");
}
