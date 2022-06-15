use crate::ln::outgoing::OutgoingContractData;
use minimint_api::db::DatabaseKeyPrefixConst;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_core::modules::ln::contracts::ContractId;

const DB_PREFIX_OUTGOING_PAYMENT: u8 = 0x40;

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingPaymentKey(pub ContractId);

impl DatabaseKeyPrefixConst for OutgoingPaymentKey {
    const DB_PREFIX: u8 = DB_PREFIX_OUTGOING_PAYMENT;
    type Key = Self;
    type Value = OutgoingContractData;
}

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingPaymentKeyPrefix;

impl DatabaseKeyPrefixConst for OutgoingPaymentKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_OUTGOING_PAYMENT;
    type Key = OutgoingPaymentKey;
    type Value = OutgoingContractData;
}
