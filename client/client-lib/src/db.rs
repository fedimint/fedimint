use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::impl_db_prefix_const;
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

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientSecretPrefixKey;

impl_db_prefix_const!(
    ClientSecretKey,
    ClientSecretPrefixKey,
    ClientSecret,
    DbKeyPrefix::ClientSecret
);
