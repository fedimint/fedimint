use fedimint_core::{Amount, TransactionId, impl_db_lookup, impl_db_record};
use fedimint_escrow_common::EscrowId;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::frost::session::{FrostDkgSession, SessionId};

#[repr(u8)]
#[derive(Debug, Clone, EnumIter, strum_macros::Display)]
pub enum DbKeyPrefix {
    FrostDkgSession = 0xb1,
    FrostDkgKeyPackages = 0xb2,
    ExternalReservedStart = 0xb0,
    CoreInternalReservedStart = 0xd0,
    CoreInternalReservedEnd = 0xff,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize)]
pub struct FrostDkgSessionKeys(pub SessionId);

#[derive(Debug)]
pub struct FrostDkgSessionPrefix;

impl_db_record!(
    key = FrostDkgSessionKeys,
    value = FrostDkgSession,
    db_prefix = DbKeyPrefix::FrostDkgSession
);

impl_db_lookup!(
    key = FrostDkgSessionKeys,
    query_prefix = FrostDkgSessionPrefix,
);

pub struct FrostDkgPackagesKeys(pub SessionId);

pub struct FrostDkgKeyPackagesPrefix;

pub struct FrostDkgKeyPackage {
    round1_secret: Vec<u8>,
    round2_secret: Vec<u8>,
    key_package: Vec<u8>,
    public_key_package: Vec<u8>,
}

impl_db_record!(
    key = FrostDkgPackagesKeys,
    value = FrostDkgKeyPackage,
    db_prefix = DbKeyPrefix::FrostDkgKeyPackages
);

impl_db_lookup!(
    key = FrostDkgPackagesKeys,
    query_prefix = FrostDkgKeyPackagesPrefix
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
    Created,
    ArbiterEngaged,
    ArbiterFeeClaimed,
}
