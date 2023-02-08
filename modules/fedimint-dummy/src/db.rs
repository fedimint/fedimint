use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::impl_db_prefix_const;
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Example = 0x80,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ExampleKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct ExampleKeyPrefix;

impl_db_prefix_const!(
    key = ExampleKey,
    value = (),
    prefix = DbKeyPrefix::Example,
    key_prefix = ExampleKeyPrefix
);
