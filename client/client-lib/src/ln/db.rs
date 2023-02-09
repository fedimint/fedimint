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
    key = OutgoingPaymentKey,
    value = OutgoingContractData,
    prefix = DbKeyPrefix::OutgoingPayment,
    key_prefix = OutgoingPaymentKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingPaymentClaimKey(pub ContractId);

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingPaymentClaimKeyPrefix;

impl_db_prefix_const!(
    key = OutgoingPaymentClaimKey,
    value = (),
    prefix = DbKeyPrefix::OutgoingPaymentClaim,
    key_prefix = OutgoingPaymentClaimKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingContractAccountKey(pub ContractId);

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingContractAccountKeyPrefix;

impl_db_prefix_const!(
    key = OutgoingContractAccountKey,
    value = OutgoingContractAccount,
    prefix = DbKeyPrefix::OutgoingContractAccount,
    key_prefix = OutgoingContractAccountKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ConfirmedInvoiceKey(pub ContractId);

#[derive(Debug, Encodable, Decodable)]
pub struct ConfirmedInvoiceKeyPrefix;

impl_db_prefix_const!(
    key = ConfirmedInvoiceKey,
    value = ConfirmedInvoice,
    prefix = DbKeyPrefix::ConfirmedInvoice,
    key_prefix = ConfirmedInvoiceKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LightningGatewayKey;

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl_db_prefix_const!(
    key = LightningGatewayKey,
    value = LightningGateway,
    prefix = DbKeyPrefix::LightningGateway,
    key_prefix = LightningGatewayKeyPrefix
);
