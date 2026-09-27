use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, TransactionId, impl_db_lookup, impl_db_record};
use fedimint_escrow_common::EscrowId;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::frost::session::{FrostDkgSession, FrostDkgSessionRecord, SessionId};

#[repr(u8)]
#[derive(Debug, Clone, EnumIter, strum_macros::Display)]
pub enum DbKeyPrefix {
    FrostDkgSession = 0xb1,
    FrostDkgSessionRecord = 0xb2,
    ExternalReservedStart = 0xb0,
    CoreInternalReservedStart = 0xd0,
    CoreInternalReservedEnd = 0xff,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct FrostDkgSessionKey(pub SessionId);

#[derive(Debug, Encodable, Decodable)]
pub struct FrostDkgSessionPrefix;

impl_db_record!(
    key = FrostDkgSessionKey,
    value = FrostDkgSession,
    db_prefix = DbKeyPrefix::FrostDkgSession
);

impl_db_lookup!(
    key = FrostDkgSessionKey,
    query_prefix = FrostDkgSessionPrefix,
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct FrostDkgSessionRecordkey(pub SessionId);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct FrostDkgSessionRecordPrefix;

impl_db_record!(
    key = FrostDkgSessionRecordkey,
    value = FrostDkgSessionRecord,
    db_prefix = DbKeyPrefix::FrostDkgSessionRecord
);

impl_db_lookup!(
    key = FrostDkgSessionRecordkey,
    query_prefix = FrostDkgSessionRecordPrefix
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowOperationMeta {
    pub escrow_id: EscrowId,
    pub amount: Amount,
    pub action: EscrowAction,
    pub txid: TransactionId,
    pub out_point_indices: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscrowAction {
    Refunded,
    Released,
    Split,
    Created,
    ArbiterEngaged,
    ArbiterFeeClaimed,
}
