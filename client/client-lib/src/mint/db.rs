use crate::mint::{CoinFinalizationData, SpendableCoin};
use minimint_api::db::DatabaseKeyPrefixConst;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::{Amount, OutPoint};
use minimint_core::modules::mint::CoinNonce;

pub const DB_PREFIX_COIN: u8 = 0x20;
pub const DB_PREFIX_OUTPUT_FINALIZATION_DATA: u8 = 0x21;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct CoinKey {
    pub amount: Amount,
    pub nonce: CoinNonce,
}

impl DatabaseKeyPrefixConst for CoinKey {
    const DB_PREFIX: u8 = DB_PREFIX_COIN;
    type Key = Self;
    type Value = SpendableCoin;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct CoinKeyPrefix;

impl DatabaseKeyPrefixConst for CoinKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_COIN;
    type Key = CoinKey;
    type Value = SpendableCoin;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OutputFinalizationKey(pub OutPoint);

impl DatabaseKeyPrefixConst for OutputFinalizationKey {
    const DB_PREFIX: u8 = DB_PREFIX_OUTPUT_FINALIZATION_DATA;
    type Key = Self;
    type Value = CoinFinalizationData;
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OutputFinalizationKeyPrefix;

impl DatabaseKeyPrefixConst for OutputFinalizationKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_OUTPUT_FINALIZATION_DATA;
    type Key = OutputFinalizationKey;
    type Value = CoinFinalizationData;
}
