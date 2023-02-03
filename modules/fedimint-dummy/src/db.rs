use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    // TODO: Make sure this does not collide with other modules
    Example = 0x80,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ExampleKey(pub u64);

impl DatabaseKeyPrefixConst for ExampleKey {
    const DB_PREFIX: u8 = DbKeyPrefix::Example as u8;
    type Key = Self;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct ExampleKeyPrefix;

impl DatabaseKeyPrefixConst for ExampleKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::Example as u8;
    type Key = ExampleKey;
    type Value = ();
}
