use fedimint_client::module::init::recovery::RecoveryFromHistoryCommon;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, Amount};
use strum::Display;
use strum_macros::EnumIter;

use crate::recovery::MintRecoveryState;
use crate::SpendableNote;

#[repr(u8)]
#[derive(Clone, Display, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Note = 0x20,
    RecoveryState = 0x21,
    RecoveryFinalized = 0x22,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNoteKey(pub SpendableNote);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNotePrefix;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNoteAmountPrefix(pub Amount);

impl_db_record!(
    key = SpendableNoteKey,
    value = (),
    db_prefix = DbKeyPrefix::Note,
);

impl_db_lookup!(key = SpendableNoteKey, query_prefix = SpendableNotePrefix);

impl_db_lookup!(
    key = SpendableNoteKey,
    query_prefix = SpendableNoteAmountPrefix
);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryStateKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RestoreStateKeyPrefix;

impl_db_record!(
    key = RecoveryStateKey,
    value = (MintRecoveryState, RecoveryFromHistoryCommon),
    db_prefix = DbKeyPrefix::RecoveryState,
);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryFinalizedKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryFinalizedKeyPrefix;

impl_db_record!(
    key = RecoveryFinalizedKey,
    value = bool,
    db_prefix = DbKeyPrefix::RecoveryFinalized,
);
