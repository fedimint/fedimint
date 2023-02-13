use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_prefix_const;
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
    db_prefix = DbKeyPrefix::Example,
    query_prefix = ExampleKeyPrefix
);
