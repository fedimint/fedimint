use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_ln_common::LightningGateway;
use lightning::routing::gossip::RoutingFees;

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    FederationConfig = 0x04,
    FederationRegistration = 0x05,
    GatewayPublicKey = 0x06,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FederationIdKey {
    pub id: FederationId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct FederationIdKeyPrefix;

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct FederationConfig {
    pub mint_channel_id: u64,
    pub timelock_delta: u64,
    pub fees: RoutingFees,
    pub config: ClientConfig,
}

impl_db_record!(
    key = FederationIdKey,
    value = FederationConfig,
    db_prefix = DbKeyPrefix::FederationConfig,
);

impl_db_lookup!(key = FederationIdKey, query_prefix = FederationIdKeyPrefix);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct FederationRegistrationKey {
    pub id: FederationId,
}

impl_db_record!(
    key = FederationRegistrationKey,
    value = LightningGateway,
    db_prefix = DbKeyPrefix::FederationRegistration,
);

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct GatewayPublicKey;

impl_db_record!(
    key = GatewayPublicKey,
    value = secp256k1::KeyPair,
    db_prefix = DbKeyPrefix::GatewayPublicKey,
);
