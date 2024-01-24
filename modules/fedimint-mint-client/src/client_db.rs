use fedimint_client::module::init::recovery::RecoveryFromHistoryCommon;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, Amount};
use fedimint_mint_common::Nonce;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::backup::recovery::MintRecoveryState;
use crate::SpendableNote;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Note = 0x20,
    NextECashNoteIndex = 0x2a,
    CancelledOOBSpend = 0x2b,
    RecoveryState = 0x2c,
    RecoveryFinalized = 0x2d,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NoteKey {
    pub amount: Amount,
    pub nonce: Nonce,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NoteKeyPrefix;

impl_db_record!(
    key = NoteKey,
    value = SpendableNote,
    db_prefix = DbKeyPrefix::Note,
);
impl_db_lookup!(key = NoteKey, query_prefix = NoteKeyPrefix);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NextECashNoteIndexKey(pub Amount);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NextECashNoteIndexKeyPrefix;

impl_db_record!(
    key = NextECashNoteIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextECashNoteIndex,
);
impl_db_lookup!(
    key = NextECashNoteIndexKey,
    query_prefix = NextECashNoteIndexKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct RecoveryStateKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RestoreStateKeyPrefix;

impl_db_record!(
    key = RecoveryStateKey,
    value = (MintRecoveryState, RecoveryFromHistoryCommon),
    db_prefix = DbKeyPrefix::RecoveryState,
);
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct RecoveryFinalizedKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryFinalizedKeyPrefix;

impl_db_record!(
    key = RecoveryFinalizedKey,
    value = bool,
    db_prefix = DbKeyPrefix::RecoveryFinalized,
);
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct CancelledOOBSpendKey(pub OperationId);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct CancelledOOBSpendKeyPrefix;

impl_db_record!(
    key = CancelledOOBSpendKey,
    value = (),
    db_prefix = DbKeyPrefix::CancelledOOBSpend,
    notify_on_modify = true,
);

impl_db_lookup!(
    key = CancelledOOBSpendKey,
    query_prefix = CancelledOOBSpendKeyPrefix,
);
