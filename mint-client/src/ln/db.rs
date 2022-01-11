use minimint::modules::ln::contracts::ContractId;
use minimint_api::db::DatabaseKeyPrefixConst;
use minimint_api::encoding::{Decodable, Encodable};

const DB_PREFIX_OUTGOING_PAYMENT: u8 = 0x40;

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingPaymentKey(pub ContractId);

impl DatabaseKeyPrefixConst for OutgoingPaymentKey {
    const DB_PREFIX: u8 = DB_PREFIX_OUTGOING_PAYMENT;
}
