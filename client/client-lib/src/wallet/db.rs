use bitcoin::Script;
use fedimint_api::core::CLIENT_KEY;
use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    PegIn = 0x22,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct PegInKey {
    pub peg_in_script: Script,
}

impl DatabaseKeyPrefixConst for PegInKey {
    const MODULE_PREFIX: u16 = CLIENT_KEY;
    const DB_PREFIX: u8 = DbKeyPrefix::PegIn as u8;
    type Key = Self;
    type Value = [u8; 32]; // TODO: introduce newtype
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PegInPrefixKey;

impl DatabaseKeyPrefixConst for PegInPrefixKey {
    const MODULE_PREFIX: u16 = CLIENT_KEY;
    const DB_PREFIX: u8 = DbKeyPrefix::PegIn as u8;
    type Key = PegInKey;
    type Value = [u8; 32];
}
