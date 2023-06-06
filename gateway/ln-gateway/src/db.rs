use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use lightning::routing::gossip::RoutingFees;
use secp256k1::KeyPair;

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    FederationConfig = 0x04,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct FederationIdKey {
    pub id: FederationId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct FederationIdKeyPrefix;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct FederationConfig {
    pub mint_channel_id: u64,
    pub redeem_key: KeyPair,
    pub timelock_delta: u64,
    pub connection_string: String,
    pub fees: RoutingFees,
}

impl_db_record!(
    key = FederationIdKey,
    value = FederationConfig,
    db_prefix = DbKeyPrefix::FederationConfig,
);

impl_db_lookup!(key = FederationIdKey, query_prefix = FederationIdKeyPrefix);
