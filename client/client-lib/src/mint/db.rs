use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, Amount, OutPoint, TieredMulti, TransactionId};
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::mint::{NoteIssuanceRequests, SpendableNote};
use crate::modules::mint::Nonce;

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

impl_db_record!(
    key = NoteKey,
    value = SpendableNote,
    db_prefix = DbKeyPrefix::Note,
);
impl_db_lookup!(key = NoteKey, query_prefix = NoteKeyPrefix);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct PendingNotesKey(pub TransactionId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PendingNotesKeyPrefix;

impl_db_record!(
    key = PendingNotesKey,
    value = TieredMulti<SpendableNote>,
    db_prefix = DbKeyPrefix::PendingNotes,
);
impl_db_lookup!(key = PendingNotesKey, query_prefix = PendingNotesKeyPrefix);

#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize, Deserialize)]
pub struct OutputFinalizationKey(pub OutPoint);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OutputFinalizationKeyPrefix;

impl_db_record!(
    key = OutputFinalizationKey,
    value = NoteIssuanceRequests,
    db_prefix = DbKeyPrefix::OutputFinalizationData,
);
impl_db_lookup!(
    key = OutputFinalizationKey,
    query_prefix = OutputFinalizationKeyPrefix
);

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
pub struct NotesPerDenominationKey;

impl_db_record!(key = NotesPerDenominationKey, value = u16, db_prefix = 0);
