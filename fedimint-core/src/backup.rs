//! Federation-stored client backups
//!
//! Federations can store client-encrypted backups to help
//! clients recover from a snapshot, instead of a blank slate.
use std::time::SystemTime;

use fedimint_core::encoding::{
    Decodable, DecodeError, Encodable, decode_field_from_finite_reader,
    decode_legacy_system_time_from_finite_reader, encode_legacy_system_time, with_decoding_context,
};
use fedimint_core::module::registry::ModuleDecoderRegistry;
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientBackupSnapshot {
    pub timestamp: SystemTime,
    #[serde(with = "fedimint_core::hex::serde")]
    pub data: Vec<u8>,
}

impl Encodable for ClientBackupSnapshot {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        encode_legacy_system_time(&self.timestamp, writer)?;
        self.data.consensus_encode(writer)
    }
}

impl Decodable for ClientBackupSnapshot {
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        decoder: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            timestamp: with_decoding_context(
                decode_legacy_system_time_from_finite_reader(decoder, modules),
                "Decoding named block field: ClientBackupSnapshot{ ... timestamp ... }",
            )?,
            data: decode_field_from_finite_reader(
                decoder,
                modules,
                "Decoding named block field: ClientBackupSnapshot{ ... data ... }",
            )?,
        })
    }
}

/// Statistics about backups stored in the federation
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct BackupStatistics {
    pub num_backups: usize,
    pub total_size: usize,
    pub refreshed_1d: usize,
    pub refreshed_1w: usize,
    pub refreshed_1m: usize,
    pub refreshed_3m: usize,
}
