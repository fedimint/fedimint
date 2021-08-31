use mint_api::db::DatabaseKeyPrefixConst;
use mint_api::encoding::{Decodable, Encodable};
use mint_api::TransactionId;
use std::fmt::Debug;

pub const DB_PREFIX_PROPOSED_TRANSACTION: u8 = 0x01;
pub const DB_PREFIX_ACCEPTED_TRANSACTION: u8 = 0x02;

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for ProposedTransactionKey {
    const DB_PREFIX: u8 = DB_PREFIX_PROPOSED_TRANSACTION;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedTransactionKeyPrefix;

impl DatabaseKeyPrefixConst for ProposedTransactionKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_PROPOSED_TRANSACTION;
}

#[derive(Debug, Encodable, Decodable)]
pub struct AcceptedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for AcceptedTransactionKey {
    const DB_PREFIX: u8 = DB_PREFIX_ACCEPTED_TRANSACTION;
}
