use bitcoin::Script;
use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};

pub const DB_PREFIX_PEG_IN: u8 = 0x22;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PegInKey {
    pub peg_in_script: Script,
}

impl DatabaseKeyPrefixConst for PegInKey {
    const DB_PREFIX: u8 = DB_PREFIX_PEG_IN;
    type Key = Self;
    type Value = [u8; 32]; // TODO: introduce newtype
}

#[derive(Debug, Clone)]
pub struct PegInPrefixKey;

impl DatabaseKeyPrefixConst for PegInPrefixKey {
    const DB_PREFIX: u8 = DB_PREFIX_PEG_IN;
    type Key = PegInKey;
    type Value = [u8; 32];
}
