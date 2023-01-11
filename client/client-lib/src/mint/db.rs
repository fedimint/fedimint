use fedimint_api::core::CLIENT_KEY;
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
    Coin = 0x20,
    OutputFinalizationData = 0x21,
    PendingCoins = 0x27,
    NextECashNoteIndex = 0x2a,
    NotesPerDenomination = 0x2b,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct CoinKey {
    pub amount: Amount,
    pub nonce: Nonce,
}

impl DatabaseKeyPrefixConst for CoinKey {
    const MODULE_PREFIX: u16 = CLIENT_KEY;
    const DB_PREFIX: u8 = DbKeyPrefix::Coin as u8;
    type Key = Self;
    type Value = SpendableNote;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct CoinKeyPrefix;

impl DatabaseKeyPrefixConst for CoinKeyPrefix {
    const MODULE_PREFIX: u16 = CLIENT_KEY;
    const DB_PREFIX: u8 = DbKeyPrefix::Coin as u8;
    type Key = CoinKey;
    type Value = SpendableNote;
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct PendingCoinsKey(pub TransactionId);

impl DatabaseKeyPrefixConst for PendingCoinsKey {
    const MODULE_PREFIX: u16 = CLIENT_KEY;
    const DB_PREFIX: u8 = DbKeyPrefix::PendingCoins as u8;
    type Key = Self;
    type Value = TieredMulti<SpendableNote>;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PendingCoinsKeyPrefix;

impl DatabaseKeyPrefixConst for PendingCoinsKeyPrefix {
    const MODULE_PREFIX: u16 = CLIENT_KEY;
    const DB_PREFIX: u8 = DbKeyPrefix::PendingCoins as u8;
    type Key = PendingCoinsKey;
    type Value = TieredMulti<SpendableNote>;
}

#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize, Deserialize)]
pub struct OutputFinalizationKey(pub OutPoint);

impl DatabaseKeyPrefixConst for OutputFinalizationKey {
    const MODULE_PREFIX: u16 = CLIENT_KEY;
    const DB_PREFIX: u8 = DbKeyPrefix::OutputFinalizationData as u8;
    type Key = Self;
    type Value = NoteIssuanceRequests;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OutputFinalizationKeyPrefix;

impl DatabaseKeyPrefixConst for OutputFinalizationKeyPrefix {
    const MODULE_PREFIX: u16 = CLIENT_KEY;
    const DB_PREFIX: u8 = DbKeyPrefix::OutputFinalizationData as u8;
    type Key = OutputFinalizationKey;
    type Value = NoteIssuanceRequests;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NextECashNoteIndexKeyPrefix;

impl DatabaseKeyPrefixConst for NextECashNoteIndexKeyPrefix {
    const MODULE_PREFIX: u16 = CLIENT_KEY;
    const DB_PREFIX: u8 = DbKeyPrefix::NextECashNoteIndex as u8;
    type Key = NextECashNoteIndexKey;
    type Value = u64;
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NextECashNoteIndexKey(pub Amount);

impl DatabaseKeyPrefixConst for NextECashNoteIndexKey {
    const MODULE_PREFIX: u16 = CLIENT_KEY;
    const DB_PREFIX: u8 = DbKeyPrefix::NextECashNoteIndex as u8;
    type Key = Self;
    type Value = u64;
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NotesPerDenominationKey;

impl DatabaseKeyPrefixConst for NotesPerDenominationKey {
    const MODULE_PREFIX: u16 = CLIENT_KEY;
    const DB_PREFIX: u8 = 0;
    type Key = Self;
    type Value = u16;
}
