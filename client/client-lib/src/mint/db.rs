use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::impl_db_prefix_const;
use fedimint_api::{Amount, OutPoint, TieredMulti, TransactionId};
use fedimint_core::modules::mint::Nonce;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::mint::{NoteIssuanceRequests, SpendableNote};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Note = 0x20,
    OutputFinalizationData = 0x21,
    PendingNotes = 0x27,
    NextECashNoteIndex = 0x2a,
    NotesPerDenomination = 0x2b,
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

impl_db_prefix_const!(NoteKey, NoteKeyPrefix, SpendableNote, DbKeyPrefix::Note);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct PendingNotesKey(pub TransactionId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PendingNotesKeyPrefix;

impl_db_prefix_const!(
    PendingNotesKey,
    PendingNotesKeyPrefix,
    TieredMulti<SpendableNote>,
    DbKeyPrefix::PendingNotes
);

#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize, Deserialize)]
pub struct OutputFinalizationKey(pub OutPoint);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OutputFinalizationKeyPrefix;

impl_db_prefix_const!(
    OutputFinalizationKey,
    OutputFinalizationKeyPrefix,
    NoteIssuanceRequests,
    DbKeyPrefix::OutputFinalizationData
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NextECashNoteIndexKey(pub Amount);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NextECashNoteIndexKeyPrefix;

impl_db_prefix_const!(
    NextECashNoteIndexKey,
    NextECashNoteIndexKeyPrefix,
    u64,
    DbKeyPrefix::NextECashNoteIndex
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NotesPerDenominationKey;

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NotesPerDenominationKeyPrefix;

impl_db_prefix_const!(
    NotesPerDenominationKey,
    NotesPerDenominationKeyPrefix,
    u16,
    0
);
