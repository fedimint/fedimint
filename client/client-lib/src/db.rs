use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};

use crate::ClientSecret;

const CLIENT_SECRET_DB_PREFIX: u8 = 0x29;

#[derive(Debug, Encodable, Decodable)]
pub struct ClientSecretKey;

impl DatabaseKeyPrefixConst for ClientSecretKey {
    const DB_PREFIX: u8 = CLIENT_SECRET_DB_PREFIX;
    type Key = ClientSecretKey;
    type Value = ClientSecret;
}
