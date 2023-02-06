use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::impl_db_prefix_const;
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

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingPaymentKeyPrefix;

impl_db_prefix_const!(
    OutgoingPaymentKey,
    OutgoingPaymentKeyPrefix,
    OutgoingContractData,
    DbKeyPrefix::OutgoingPayment
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingPaymentClaimKey(pub ContractId);

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingPaymentClaimKeyPrefix;

impl_db_prefix_const!(
    OutgoingPaymentClaimKey,
    OutgoingPaymentClaimKeyPrefix,
    (),
    DbKeyPrefix::OutgoingPaymentClaim
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingContractAccountKey(pub ContractId);

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingContractAccountKeyPrefix;

impl_db_prefix_const!(
    OutgoingContractAccountKey,
    OutgoingContractAccountKeyPrefix,
    OutgoingContractAccount,
    DbKeyPrefix::OutgoingContractAccount
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ConfirmedInvoiceKey(pub ContractId);

#[derive(Debug, Encodable, Decodable)]
pub struct ConfirmedInvoiceKeyPrefix;

impl_db_prefix_const!(
    ConfirmedInvoiceKey,
    ConfirmedInvoiceKeyPrefix,
    ConfirmedInvoice,
    DbKeyPrefix::ConfirmedInvoice
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LightningGatewayKey;

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl_db_prefix_const!(
    LightningGatewayKey,
    LightningGatewayKeyPrefix,
    LightningGateway,
    DbKeyPrefix::LightningGateway
);
