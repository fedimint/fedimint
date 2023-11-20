use std::time::SystemTime;

use bitcoin_hashes::sha256;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_ln_common::LightningGatewayRegistration;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::OutgoingLightningPayment;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    LightningGateway = 0x28,
    PaymentResult = 0x29,
    MetaOverrides = 0x30,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LightningGatewayKey;

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl_db_record!(
    key = LightningGatewayKey,
    value = LightningGatewayRegistration,
    db_prefix = DbKeyPrefix::LightningGateway,
);
impl_db_lookup!(
    key = LightningGatewayKey,
    query_prefix = LightningGatewayKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct PaymentResultKey {
    pub payment_hash: sha256::Hash,
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct PaymentResultPrefix;

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct PaymentResult {
    pub index: u16,
    pub completed_payment: Option<OutgoingLightningPayment>,
}

impl_db_record!(
    key = PaymentResultKey,
    value = PaymentResult,
    db_prefix = DbKeyPrefix::PaymentResult,
);

impl_db_lookup!(key = PaymentResultKey, query_prefix = PaymentResultPrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct MetaOverridesKey;

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct MetaOverridesPrefix;

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct MetaOverrides {
    pub value: String,
    pub fetched_at: SystemTime,
}

impl_db_record!(
    key = MetaOverridesKey,
    value = MetaOverrides,
    db_prefix = DbKeyPrefix::MetaOverrides,
);

impl_db_lookup!(key = MetaOverridesKey, query_prefix = MetaOverridesPrefix);
