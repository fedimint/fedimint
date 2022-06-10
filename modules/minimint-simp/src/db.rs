use crate::Account;
use crate::ProgramId;
use minimint_api::db::DatabaseKeyPrefixConst;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::OutPoint;

const DB_PREFIX_PROGRAM: u8 = 0x40;
const DB_PREFIX_PROGRAM_UPDATE: u8 = 0x44;

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ProgramKey(pub ProgramId);

impl DatabaseKeyPrefixConst for ProgramKey {
    const DB_PREFIX: u8 = DB_PREFIX_PROGRAM;
    type Key = Self;
    type Value = Account;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProgramUpdateKey(pub OutPoint);

impl DatabaseKeyPrefixConst for ProgramUpdateKey {
    const DB_PREFIX: u8 = DB_PREFIX_PROGRAM_UPDATE;
    type Key = Self;
    type Value = ProgramId;
}
