//! Federation-stored client backups
//!
//! Federations can store client-encrypted backups to help
//! clients recover from a snapshot, instead of a blank slate.
use std::time::SystemTime;

use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use serde::{Deserialize, Serialize};

use crate::db::DbKeyPrefix;

/// Key used to store user's ecash backups
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct ClientBackupKey(pub secp256k1::PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct ClientBackupKeyPrefix;

impl_db_record!(
    key = ClientBackupKey,
    value = ClientBackupSnapshot,
    db_prefix = DbKeyPrefix::ClientBackup,
);
impl_db_lookup!(key = ClientBackupKey, query_prefix = ClientBackupKeyPrefix);

/// User's backup, received at certain time, containing encrypted payload
#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize, Deserialize)]
pub struct ClientBackupSnapshot {
    pub timestamp: SystemTime,
    #[serde(with = "fedimint_core::hex::serde")]
    pub data: Vec<u8>,
}

/// Statistics about backups stored in the federation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackupStatistics {
    pub num_backups: usize,
    pub total_size: usize,
    pub refreshed_1d: usize,
    pub refreshed_1w: usize,
    pub refreshed_1m: usize,
    pub refreshed_3m: usize,
}
