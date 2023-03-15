use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use lightning_invoice::Invoice;
use serde::Serialize;
use strum_macros::EnumIter;

use super::incoming::ConfirmedInvoice;
use super::outgoing::OutgoingContractAccount;
use crate::ln::outgoing::OutgoingContractData;
use crate::modules::ln::contracts::ContractId;
use crate::modules::ln::LightningGateway;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    OutgoingPayment = 0x23,
    OutgoingPaymentClaim = 0x24,
    OutgoingContractAccount = 0x25,
    ConfirmedInvoice = 0x26,
    LightningGateway = 0x28,
    OutgoingContractPending = 0x2c,
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

impl_db_record!(
    key = OutgoingPaymentKey,
    value = OutgoingContractData,
    db_prefix = DbKeyPrefix::OutgoingPayment,
);
impl_db_lookup!(
    key = OutgoingPaymentKey,
    query_prefix = OutgoingPaymentKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingPaymentClaimKey(pub ContractId);

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingPaymentClaimKeyPrefix;

impl_db_record!(
    key = OutgoingPaymentClaimKey,
    value = (),
    db_prefix = DbKeyPrefix::OutgoingPaymentClaim,
);
impl_db_lookup!(
    key = OutgoingPaymentClaimKey,
    query_prefix = OutgoingPaymentClaimKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingContractAccountKey(pub ContractId);

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingContractAccountKeyPrefix;

impl_db_record!(
    key = OutgoingContractAccountKey,
    value = OutgoingContractAccount,
    db_prefix = DbKeyPrefix::OutgoingContractAccount,
);
impl_db_lookup!(
    key = OutgoingContractAccountKey,
    query_prefix = OutgoingContractAccountKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ConfirmedInvoiceKey(pub ContractId);

#[derive(Debug, Encodable, Decodable)]
pub struct ConfirmedInvoiceKeyPrefix;

impl_db_record!(
    key = ConfirmedInvoiceKey,
    value = ConfirmedInvoice,
    db_prefix = DbKeyPrefix::ConfirmedInvoice,
);
impl_db_lookup!(
    key = ConfirmedInvoiceKey,
    query_prefix = ConfirmedInvoiceKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LightningGatewayKey;

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl_db_record!(
    key = LightningGatewayKey,
    value = LightningGateway,
    db_prefix = DbKeyPrefix::LightningGateway,
);
impl_db_lookup!(
    key = LightningGatewayKey,
    query_prefix = LightningGatewayKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingContractPendingKey(pub Sha256Hash);

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingContractPendingKeyPrefix;

impl_db_record!(
    key = OutgoingContractPendingKey,
    value = Invoice,
    db_prefix = DbKeyPrefix::OutgoingContractPending,
);
impl_db_lookup!(
    key = OutgoingContractPendingKey,
    query_prefix = OutgoingContractPendingKeyPrefix
);
