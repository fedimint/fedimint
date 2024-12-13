use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::SafeUrl;
use fedimint_core::{impl_db_lookup, impl_db_record};

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    Gateway = 0x41,
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
pub struct GatewayKey(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct GatewayPrefix;

impl_db_record!(
    key = GatewayKey,
    value = SafeUrl,
    db_prefix = DbKeyPrefix::Gateway,
);
impl_db_lookup!(key = GatewayKey, query_prefix = GatewayPrefix);
