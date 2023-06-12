use std::time::Duration;

use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_ln_common::LightningGateway;
use lightning::routing::gossip::RoutingFees;
use secp256k1::{KeyPair, PublicKey};
use url::Url;

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    FederationConfig = 0x04,
    FederationRegistration = 0x05,
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
    pub redeem_key: KeyPair,
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

impl FederationConfig {
    pub fn to_gateway_registration_info(
        &self,
        route_hints: Vec<RouteHint>,
        time_to_live: Duration,
        node_pub_key: PublicKey,
        api: Url,
    ) -> LightningGateway {
        LightningGateway {
            mint_channel_id: self.mint_channel_id,
            mint_pub_key: self.redeem_key.x_only_public_key().0,
            node_pub_key,
            api,
            route_hints,
            valid_until: fedimint_core::time::now() + time_to_live,
            fees: self.fees,
        }
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct FederationRegistrationKey {
    pub id: FederationId,
}

impl_db_record!(
    key = FederationRegistrationKey,
    value = LightningGateway,
    db_prefix = DbKeyPrefix::FederationRegistration,
);
