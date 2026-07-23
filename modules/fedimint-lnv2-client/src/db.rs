use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::util::SafeUrl;
use fedimint_core::{impl_db_lookup, impl_db_record};
use strum::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    #[allow(dead_code)]
    /// Historically mapped a lightning node public key to a gateway api
    /// endpoint. Superseded by the in-memory gateway cache, which is seeded
    /// from the persisted gateway list under [`CachedGatewayKey`].
    Gateway = 0x41,
    IncomingContractStreamIndex = 0x42,
    CachedGateways = 0x43,
    #[allow(dead_code)]
    /// Prefixes between 0xb0..=0xcf shall all be considered allocated for
    /// historical and future external use
    ExternalReservedStart = 0xb0,
    #[allow(dead_code)]
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedStart = 0xd0,
    #[allow(dead_code)]
    CoreInternalReservedEnd = 0xff,
}

#[derive(Debug, Encodable, Decodable)]
pub struct IncomingContractStreamIndexKey;

impl_db_record!(
    key = IncomingContractStreamIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::IncomingContractStreamIndex
);

/// One row per registered gateway, mirrored to the database by the gateway
/// update task. Persisting the list lets lnurl generation read it without a
/// network round trip and seeds the in-memory cache on a cold start before the
/// consensus gateway query returns.
#[derive(Debug, Encodable, Decodable)]
pub struct CachedGatewayKey(pub SafeUrl);

#[derive(Debug, Encodable, Decodable)]
pub struct CachedGatewayPrefix;

impl_db_record!(
    key = CachedGatewayKey,
    value = (),
    db_prefix = DbKeyPrefix::CachedGateways,
);

impl_db_lookup!(key = CachedGatewayKey, query_prefix = CachedGatewayPrefix,);
