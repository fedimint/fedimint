use bitcoin::Network;
use bitcoin_hashes::sha256;
use fedimint_core::api::InviteCode;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_ln_common::serde_routing_fees;
use lightning_invoice::RoutingFees;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    FederationConfig = 0x04,
    FederationRegistration = 0x05,
    GatewayPublicKey = 0x06,
    GatewayConfiguration = 0x07,
    PreimageAuthentication = 0x08,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FederationIdKey {
    pub id: FederationId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct FederationIdKeyPrefix;

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct FederationConfig {
    pub invite_code: InviteCode,
    pub mint_channel_id: u64,
    pub timelock_delta: u64,
    #[serde(with = "serde_routing_fees")]
    pub fees: RoutingFees,
}

impl_db_record!(
    key = FederationIdKey,
    value = FederationConfig,
    db_prefix = DbKeyPrefix::FederationConfig,
);

impl_db_lookup!(key = FederationIdKey, query_prefix = FederationIdKeyPrefix);

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct GatewayPublicKey;

impl_db_record!(
    key = GatewayPublicKey,
    value = secp256k1::KeyPair,
    db_prefix = DbKeyPrefix::GatewayPublicKey,
);

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct GatewayConfigurationKey;

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct GatewayConfiguration {
    pub password: String,
    pub num_route_hints: u32,
    #[serde(with = "serde_routing_fees")]
    pub routing_fees: RoutingFees,
    pub network: Network,
}

impl_db_record!(
    key = GatewayConfigurationKey,
    value = GatewayConfiguration,
    db_prefix = DbKeyPrefix::GatewayConfiguration,
    notify_on_modify = true,
);

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct PreimageAuthentication {
    pub payment_hash: sha256::Hash,
}

impl_db_record!(
    key = PreimageAuthentication,
    value = sha256::Hash,
    db_prefix = DbKeyPrefix::PreimageAuthentication
);
