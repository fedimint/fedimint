use crate::ln::outgoing::OutgoingContractData;
use minimint_api::db::DatabaseKeyPrefixConst;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_core::modules::ln::contracts::ContractId;

use super::incoming::ConfirmedInvoice;

const DB_PREFIX_OUTGOING_PAYMENT: u8 = 0x40;
const DB_PREFIX_CONFIRMED_INVOICE: u8 = 0x45;

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

#[derive(Debug, Encodable, Decodable)]
pub struct ConfirmedInvoiceKey(pub ContractId);

impl DatabaseKeyPrefixConst for ConfirmedInvoiceKey {
    const DB_PREFIX: u8 = DB_PREFIX_CONFIRMED_INVOICE;
    type Key = Self;
    type Value = ConfirmedInvoice;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ConfirmedInvoiceKeyPrefix;

impl DatabaseKeyPrefixConst for ConfirmedInvoiceKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_CONFIRMED_INVOICE;
    type Key = ConfirmedInvoiceKey;
    type Value = ConfirmedInvoice;
}
