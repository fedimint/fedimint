use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_core::modules::ln::contracts::ContractId;
use fedimint_core::modules::ln::LightningGateway;
use serde::Serialize;
use strum_macros::EnumIter;

use super::incoming::ConfirmedInvoice;
use super::outgoing::OutgoingContractAccount;
use crate::ln::outgoing::OutgoingContractData;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    OutgoingPayment = 0x23,
    OutgoingPaymentClaim = 0x24,
    OutgoingContractAccount = 0x25,
    ConfirmedInvoice = 0x26,
    LightningGateway = 0x28,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingPaymentKey(pub ContractId);

impl DatabaseKeyPrefixConst for OutgoingPaymentKey {
    const DB_PREFIX: u8 = DbKeyPrefix::OutgoingPayment as u8;
    type Key = Self;
    type Value = OutgoingContractData;
}

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingPaymentKeyPrefix;

impl DatabaseKeyPrefixConst for OutgoingPaymentKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::OutgoingPayment as u8;
    type Key = OutgoingPaymentKey;
    type Value = OutgoingContractData;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingPaymentClaimKey(pub ContractId);

impl DatabaseKeyPrefixConst for OutgoingPaymentClaimKey {
    const DB_PREFIX: u8 = DbKeyPrefix::OutgoingPaymentClaim as u8;
    type Key = Self;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingPaymentClaimKeyPrefix;

impl DatabaseKeyPrefixConst for OutgoingPaymentClaimKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::OutgoingPaymentClaim as u8;
    type Key = OutgoingPaymentClaimKey;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingContractAccountKey(pub ContractId);

impl DatabaseKeyPrefixConst for OutgoingContractAccountKey {
    const DB_PREFIX: u8 = DbKeyPrefix::OutgoingContractAccount as u8;
    type Key = Self;
    type Value = OutgoingContractAccount;
}

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingContractAccountKeyPrefix;

impl DatabaseKeyPrefixConst for OutgoingContractAccountKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::OutgoingContractAccount as u8;
    type Key = OutgoingContractAccountKey;
    type Value = OutgoingContractAccount;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ConfirmedInvoiceKey(pub ContractId);

impl DatabaseKeyPrefixConst for ConfirmedInvoiceKey {
    const DB_PREFIX: u8 = DbKeyPrefix::ConfirmedInvoice as u8;
    type Key = Self;
    type Value = ConfirmedInvoice;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ConfirmedInvoiceKeyPrefix;

impl DatabaseKeyPrefixConst for ConfirmedInvoiceKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::ConfirmedInvoice as u8;
    type Key = ConfirmedInvoiceKey;
    type Value = ConfirmedInvoice;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LightningGatewayKey;

impl DatabaseKeyPrefixConst for LightningGatewayKey {
    const DB_PREFIX: u8 = DbKeyPrefix::LightningGateway as u8;
    type Key = Self;
    type Value = LightningGateway;
}

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl DatabaseKeyPrefixConst for LightningGatewayKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::LightningGateway as u8;
    type Key = LightningGatewayKey;
    type Value = LightningGateway;
}
