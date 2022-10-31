use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::{Amount, OutPoint, TieredMulti, TransactionId};
use fedimint_core::modules::mint::Nonce;

use crate::mint::{NoteIssuanceRequests, SpendableNote};

#[repr(u8)]
#[derive(Clone)]
pub enum DbKeyPrefix {
    Coin = 0x20,
    OutputFinalizationData = 0x21,
    PendingCoins = 0x27,
    LastECashNoteIndex = 0x2a,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct CoinKey {
    pub amount: Amount,
    pub nonce: Nonce,
}

impl DatabaseKeyPrefixConst for CoinKey {
    const DB_PREFIX: u8 = DbKeyPrefix::Coin as u8;
    type Key = Self;
    type Value = SpendableNote;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct CoinKeyPrefix;

impl DatabaseKeyPrefixConst for CoinKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::Coin as u8;
    type Key = CoinKey;
    type Value = SpendableNote;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PendingCoinsKey(pub TransactionId);

impl DatabaseKeyPrefixConst for PendingCoinsKey {
    const DB_PREFIX: u8 = DbKeyPrefix::PendingCoins as u8;
    type Key = Self;
    type Value = TieredMulti<SpendableNote>;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PendingCoinsKeyPrefix;

impl DatabaseKeyPrefixConst for PendingCoinsKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::PendingCoins as u8;
    type Key = PendingCoinsKey;
    type Value = TieredMulti<SpendableNote>;
}

#[derive(Debug, Clone, Encodable, Decodable)]
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
pub struct LastECashNoteIndexKey;

impl DatabaseKeyPrefixConst for LastECashNoteIndexKey {
    const DB_PREFIX: u8 = DbKeyPrefix::LastECashNoteIndex as u8;
    type Key = Self;
    type Value = u64;
}
