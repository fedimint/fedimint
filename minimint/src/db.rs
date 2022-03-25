use crate::consensus::AcceptedTransaction;
use crate::transaction::Transaction;
use minimint_api::db::DatabaseKeyPrefixConst;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::TransactionId;
use std::fmt::Debug;

pub const DB_PREFIX_PROPOSED_TRANSACTION: u8 = 0x01;
pub const DB_PREFIX_ACCEPTED_TRANSACTION: u8 = 0x02;

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for ProposedTransactionKey {
    const DB_PREFIX: u8 = DB_PREFIX_PROPOSED_TRANSACTION;
    type Key = Self;
    type Value = Transaction;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedTransactionKeyPrefix;

impl DatabaseKeyPrefixConst for ProposedTransactionKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_PROPOSED_TRANSACTION;
    type Key = ProposedTransactionKey;
    type Value = Transaction;
}

#[derive(Debug, Encodable, Decodable)]
pub struct AcceptedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for AcceptedTransactionKey {
    const DB_PREFIX: u8 = DB_PREFIX_ACCEPTED_TRANSACTION;
    type Key = Self;
    type Value = AcceptedTransaction;
}
