use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::SafeUrl;
use fedimint_core::{impl_db_lookup, impl_db_record};

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    Gateway = 0x41,
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
