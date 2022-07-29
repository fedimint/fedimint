use crate::ln::outgoing::OutgoingContractData;
use minimint_api::db::DatabaseKeyPrefixConst;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_core::modules::ln::contracts::ContractId;
use minimint_core::modules::ln::LightningGateway;

use super::incoming::ConfirmedInvoice;
use super::outgoing::OutgoingContractAccount;

const DB_PREFIX_OUTGOING_PAYMENT: u8 = 0x23;
const DB_PREFIX_OUTGOING_PAYMENT_CLAIM: u8 = 0x24;
const DB_PREFIX_OUTGOING_CONTRACT_ACCOUNT: u8 = 0x25;
const DB_PREFIX_CONFIRMED_INVOICE: u8 = 0x26;
const DB_PREFIX_LIGHTNING_GATEWAY: u8 = 0x28;

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
pub struct OutgoingPaymentClaimKey(pub ContractId);

impl DatabaseKeyPrefixConst for OutgoingPaymentClaimKey {
    const DB_PREFIX: u8 = DB_PREFIX_OUTGOING_PAYMENT_CLAIM;
    type Key = Self;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingPaymentClaimKeyPrefix;

impl DatabaseKeyPrefixConst for OutgoingPaymentClaimKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_OUTGOING_PAYMENT_CLAIM;
    type Key = OutgoingPaymentClaimKey;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingContractAccountKey(pub ContractId);

impl DatabaseKeyPrefixConst for OutgoingContractAccountKey {
    const DB_PREFIX: u8 = DB_PREFIX_OUTGOING_CONTRACT_ACCOUNT;
    type Key = Self;
    type Value = OutgoingContractAccount;
}

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingContractAccountKeyPrefix;

impl DatabaseKeyPrefixConst for OutgoingContractAccountKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_OUTGOING_CONTRACT_ACCOUNT;
    type Key = OutgoingContractAccountKey;
    type Value = OutgoingContractAccount;
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

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKey;

impl DatabaseKeyPrefixConst for LightningGatewayKey {
    const DB_PREFIX: u8 = DB_PREFIX_LIGHTNING_GATEWAY;
    type Key = Self;
    type Value = LightningGateway;
}
