use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use serde::Serialize;
use strum_macros::EnumIter;

/// Namespaces DB keys for this module
#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Example = 0x01,
}

// TODO: Boilerplate-code
impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct EmptyExampleKey(#[serde(with = "::fedimint_core::encoding::as_hex")] pub Vec<u8>);

#[derive(Debug, Encodable, Decodable)]
pub struct EmptyExampleKeyPrefix;

impl_db_record!(
    key = EmptyExampleKey,
    value = Vec<u8>,
    db_prefix = DbKeyPrefix::Example,
);
impl_db_lookup!(key = EmptyExampleKey, query_prefix = EmptyExampleKeyPrefix,);
