use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_ln_common::LightningGateway;
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    LightningGateway = 0x28,
    NextIncomingContractIndexKey = 0x29,
    NextOutgoingContractIndexKey = 0x30,
}

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
pub(crate) struct NextIncomingContractIndexKey;

impl_db_record!(
    key = NextIncomingContractIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextIncomingContractIndexKey,
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub(crate) struct NextOutgoingContractIndexKey;

impl_db_record!(
    key = NextOutgoingContractIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextOutgoingContractIndexKey,
);
