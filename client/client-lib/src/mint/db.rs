use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_prefix_const, Amount, OutPoint, TieredMulti, TransactionId};
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

impl_db_prefix_const!(
    key = NoteKey,
    value = SpendableNote,
    db_prefix = DbKeyPrefix::Note,
    query_prefix = NoteKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct PendingNotesKey(pub TransactionId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PendingNotesKeyPrefix;

impl_db_prefix_const!(
    key = PendingNotesKey,
    value = TieredMulti<SpendableNote>,
    db_prefix = DbKeyPrefix::PendingNotes,
    query_prefix = PendingNotesKeyPrefix
);

#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize, Deserialize)]
pub struct OutputFinalizationKey(pub OutPoint);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OutputFinalizationKeyPrefix;

impl_db_prefix_const!(
    key = OutputFinalizationKey,
    value = NoteIssuanceRequests,
    db_prefix = DbKeyPrefix::OutputFinalizationData,
    query_prefix = OutputFinalizationKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NextECashNoteIndexKey(pub Amount);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NextECashNoteIndexKeyPrefix;

impl_db_prefix_const!(
    key = NextECashNoteIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextECashNoteIndex,
    query_prefix = NextECashNoteIndexKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NotesPerDenominationKey;

impl_db_prefix_const!(key = NotesPerDenominationKey, value = u16, db_prefix = 0);
