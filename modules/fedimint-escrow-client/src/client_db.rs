use fedimint_core::{Amount, TransactionId};
use fedimint_escrow_common::EscrowId;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Debug, Clone, EnumIter, strum_macros::Display)]
pub enum DbKeyPrefix {
    ExternalReservedStart = 0xb0,
    CoreInternalReservedStart = 0xd0,
    CoreInternalReservedEnd = 0xff,
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
    ArbiterFeeClaimed,
}
