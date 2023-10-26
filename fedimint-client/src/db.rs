use fedimint_core::api::{ApiVersionSet, InviteCode};
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use serde::Serialize;
use strum_macros::EnumIter;

use crate::oplog::OperationLogEntry;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    EncodedClientSecret = 0x28,
    ClientSecret = 0x29,
    OperationLog = 0x2c,
    ChronologicalOperationLog = 0x2d,
    CommonApiVersionCache = 0x2e,
    ClientConfig = 0x2f,
    ClientInviteCode = 0x30,
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
