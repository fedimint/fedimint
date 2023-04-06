use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::ClientSecret;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    ClientSecret = 0x29,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientSecretKey;

impl_db_record!(
    key = ClientSecretKey,
    value = ClientSecret,
    db_prefix = DbKeyPrefix::ClientSecret
);
