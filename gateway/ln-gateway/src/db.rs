use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_ln_common::LightningGateway;
use lightning::routing::gossip::RoutingFees;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    FederationConfig = 0x04,
    FederationRegistration = 0x05,
    GatewayPublicKey = 0x06,
    GatewayConfiguration = 0x07,
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

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct FederationConfig {
    pub mint_channel_id: u64,
    pub timelock_delta: u64,
    pub fees: RoutingFees,
    pub config: ClientConfig,
}

impl Serialize for FederationConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("FederationConfig", 5)?;
        state.serialize_field("mint_channel_id", &self.mint_channel_id)?;
        state.serialize_field("timelock_delta", &self.timelock_delta)?;
        state.serialize_field("config", &self.config)?;
        state.serialize_field("base_msat", &self.fees.base_msat)?;
        state.serialize_field(
            "proportional_millionths",
            &self.fees.proportional_millionths,
        )?;
        state.end()
    }
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

#[derive(Debug, Encodable, Decodable)]
pub struct FederationRegistrationKeyPrefix;

impl_db_lookup!(
    key = FederationRegistrationKey,
    query_prefix = FederationRegistrationKeyPrefix
);

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
}

impl_db_record!(
    key = GatewayConfigurationKey,
    value = GatewayConfiguration,
    db_prefix = DbKeyPrefix::GatewayConfiguration,
    notify_on_modify = true,
);
