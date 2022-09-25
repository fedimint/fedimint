use crate::mint::{NoteIssuanceRequests, SpendableNote};
use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::{Amount, OutPoint, TransactionId};
use fedimint_core::modules::mint::tiered::TieredMulti;
use fedimint_core::modules::mint::Nonce;

pub const DB_PREFIX_COIN: u8 = 0x20;
pub const DB_PREFIX_OUTPUT_FINALIZATION_DATA: u8 = 0x21;
pub const DB_PREFIX_PENDING_COINS: u8 = 0x27;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct CoinKey {
    pub amount: Amount,
    pub nonce: Nonce,
}

impl DatabaseKeyPrefixConst for CoinKey {
    const DB_PREFIX: u8 = DB_PREFIX_COIN;
    type Key = Self;
    type Value = SpendableNote;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct CoinKeyPrefix;

impl DatabaseKeyPrefixConst for CoinKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_COIN;
    type Key = CoinKey;
    type Value = SpendableNote;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PendingCoinsKey(pub TransactionId);

impl DatabaseKeyPrefixConst for PendingCoinsKey {
    const DB_PREFIX: u8 = DB_PREFIX_PENDING_COINS;
    type Key = Self;
    type Value = TieredMulti<SpendableNote>;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PendingCoinsKeyPrefix;

impl DatabaseKeyPrefixConst for PendingCoinsKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_PENDING_COINS;
    type Key = PendingCoinsKey;
    type Value = TieredMulti<SpendableNote>;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OutputFinalizationKey(pub OutPoint);

impl DatabaseKeyPrefixConst for OutputFinalizationKey {
    const DB_PREFIX: u8 = DB_PREFIX_OUTPUT_FINALIZATION_DATA;
    type Key = Self;
    type Value = NoteIssuanceRequests;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OutputFinalizationKeyPrefix;

impl DatabaseKeyPrefixConst for OutputFinalizationKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_OUTPUT_FINALIZATION_DATA;
    type Key = OutputFinalizationKey;
    type Value = NoteIssuanceRequests;
}
