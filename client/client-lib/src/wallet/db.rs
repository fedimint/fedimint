use bitcoin::Script;
use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::impl_db_prefix_const;
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

impl_db_prefix_const!(PegInKey, PegInPrefixKey, [u8; 32], DbKeyPrefix::PegIn);
