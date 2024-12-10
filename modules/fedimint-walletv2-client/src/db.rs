use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
use serde::Serialize;
use strum_macros::EnumIter;

// #[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {
    AddressCounter = 0x30,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct AddressCounterKey;

impl_db_record!(
    key = AddressCounterKey,
    value = u64,
    db_prefix = DbKeyPrefix::AddressCounter
);
