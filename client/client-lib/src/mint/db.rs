use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
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
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NoteKey {
    pub amount: Amount,
    pub nonce: Nonce,
}

impl DatabaseKeyPrefixConst for NoteKey {
    const DB_PREFIX: u8 = DbKeyPrefix::Note as u8;
    type Key = Self;
    type Value = SpendableNote;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NoteKeyPrefix;

impl DatabaseKeyPrefixConst for NoteKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::Note as u8;
    type Key = NoteKey;
    type Value = SpendableNote;
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct PendingNotesKey(pub TransactionId);

impl DatabaseKeyPrefixConst for PendingNotesKey {
    const DB_PREFIX: u8 = DbKeyPrefix::PendingNotes as u8;
    type Key = Self;
    type Value = TieredMulti<SpendableNote>;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PendingNotesKeyPrefix;

impl DatabaseKeyPrefixConst for PendingNotesKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::PendingNotes as u8;
    type Key = PendingNotesKey;
    type Value = TieredMulti<SpendableNote>;
}

#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize, Deserialize)]
pub struct OutputFinalizationKey(pub OutPoint);

impl DatabaseKeyPrefixConst for OutputFinalizationKey {
    const DB_PREFIX: u8 = DbKeyPrefix::OutputFinalizationData as u8;
    type Key = Self;
    type Value = NoteIssuanceRequests;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OutputFinalizationKeyPrefix;

impl DatabaseKeyPrefixConst for OutputFinalizationKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::OutputFinalizationData as u8;
    type Key = OutputFinalizationKey;
    type Value = NoteIssuanceRequests;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NextECashNoteIndexKeyPrefix;

impl DatabaseKeyPrefixConst for NextECashNoteIndexKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::NextECashNoteIndex as u8;
    type Key = NextECashNoteIndexKey;
    type Value = u64;
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NextECashNoteIndexKey(pub Amount);

impl DatabaseKeyPrefixConst for NextECashNoteIndexKey {
    const DB_PREFIX: u8 = DbKeyPrefix::NextECashNoteIndex as u8;
    type Key = Self;
    type Value = u64;
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NotesPerDenominationKey;

impl DatabaseKeyPrefixConst for NotesPerDenominationKey {
    const DB_PREFIX: u8 = 0;
    type Key = Self;
    type Value = u16;
}
