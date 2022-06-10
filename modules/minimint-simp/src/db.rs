use crate::contracts::ContractId;
use crate::AccountContract;
use minimint_api::db::DatabaseKeyPrefixConst;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::OutPoint;

const DB_PREFIX_CONTRACT: u8 = 0x40;
const DB_PREFIX_CONTRACT_UPDATE: u8 = 0x44;

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractKey(pub ContractId);

impl DatabaseKeyPrefixConst for ContractKey {
    const DB_PREFIX: u8 = DB_PREFIX_CONTRACT;
    type Key = Self;
    type Value = AccountContract;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ContractUpdateKey(pub OutPoint);

impl DatabaseKeyPrefixConst for ContractUpdateKey {
    const DB_PREFIX: u8 = DB_PREFIX_CONTRACT_UPDATE;
    type Key = Self;
    type Value = ContractId;
}
