use fedimint_client_module::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, TransactionId, impl_db_lookup, impl_db_record};
use fedimint_escrow_common::EscrowId;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Debug, Clone, EnumIter, strum_macros::Display)]
pub enum DbKeyPrefix {
    ClientEscrows = 0x04,
    /// Prefixes between 0xb0..=0xcf shall all be considered allocated for
    /// historical and future external use
    ExternalReservedStart = 0xb0,
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedStart = 0xd0,
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedEnd = 0xff,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
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
