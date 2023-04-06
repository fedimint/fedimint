use bitcoin::Script;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    PegIn = 0x22,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct PegInKey {
    pub peg_in_script: Script,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PegInPrefixKey;

impl_db_record!(
    key = PegInKey,
    value = [u8; 32],
    db_prefix = DbKeyPrefix::PegIn,
);
impl_db_lookup!(key = PegInKey, query_prefix = PegInPrefixKey);
