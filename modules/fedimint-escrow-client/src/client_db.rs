use fedimint_client_module::OperationId;
use fedimint_client_module::module::init::recovery::RecoveryFromHistoryCommon;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, TransactionId, impl_db_lookup, impl_db_record};
use fedimint_escrow_common::EscrowId;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::backup::EscrowRecovery;

#[repr(u8)]
#[derive(Debug, Clone, EnumIter, strum_macros::Display)]
pub enum DbKeyPrefix {
    ClientEscrows = 0x04,
    RecoveryState = 0x08,
    RecoveryFinalized = 0x09,
    ExternalReservedStart = 0xb0,
    CoreInternalReservedStart = 0xd0,
    CoreInternalReservedEnd = 0xff,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable, PartialEq, Eq)]
pub struct EscrowClientRecord {
    pub escrow_id: EscrowId,
    pub operation_id: OperationId,
    pub amount: Amount,
    pub status: EscrowClientStatus,
}

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
    Created,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable, PartialEq, Eq)]
pub enum EscrowClientStatus {
    Creating,
    Active,
    Released,
    Refunded,
    Failed { reason: String },
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ClientEscrowKey(pub EscrowId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct ClientEscrowKeyPrefix;

impl_db_record!(
    key = ClientEscrowKey,
    value = EscrowClientRecord,
    db_prefix = DbKeyPrefix::ClientEscrows,
);

impl_db_lookup!(key = ClientEscrowKey, query_prefix = ClientEscrowKeyPrefix);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct EscrowRecoveryStateKey;

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct EscrowRecoveryFinalizedKey;

impl_db_record!(
    key = EscrowRecoveryStateKey,
    value = (EscrowRecovery, RecoveryFromHistoryCommon),
    db_prefix = crate::client_db::DbKeyPrefix::RecoveryState,
);

impl_db_record!(
    key = EscrowRecoveryFinalizedKey,
    value = bool,
    db_prefix = crate::client_db::DbKeyPrefix::RecoveryFinalized,
);
