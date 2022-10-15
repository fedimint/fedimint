use std::fmt::Debug;

use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable, ModuleRegistry};
use fedimint_api::{PeerId, TransactionId};
use fedimint_core::epoch::EpochHistory;

use crate::consensus::AcceptedTransaction;
use crate::transaction::Transaction;

pub const DB_PREFIX_PROPOSED_TRANSACTION: u8 = 0x01;
pub const DB_PREFIX_ACCEPTED_TRANSACTION: u8 = 0x02;
pub const DB_PREFIX_DROP_PEER: u8 = 0x03;
pub const DB_PREFIX_REJECTED_TRANSACTION: u8 = 0x04;
pub const DB_PREFIX_EPOCH_HISTORY: u8 = 0x05;
pub const DB_PREFIX_LAST_EPOCH: u8 = 0x06;

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

#[derive(Debug, Encodable, Decodable)]
pub struct RejectedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for RejectedTransactionKey {
    const DB_PREFIX: u8 = DB_PREFIX_REJECTED_TRANSACTION;
    type Key = Self;
    type Value = String;
}

#[derive(Debug, Encodable, Decodable)]
pub struct DropPeerKey(pub PeerId);

impl DatabaseKeyPrefixConst for DropPeerKey {
    const DB_PREFIX: u8 = DB_PREFIX_DROP_PEER;
    type Key = Self;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct DropPeerKeyPrefix;

impl DatabaseKeyPrefixConst for DropPeerKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_DROP_PEER;
    type Key = DropPeerKey;
    type Value = ();
}

#[derive(Debug, Copy, Clone, Encodable, Decodable)]
pub struct EpochHistoryKey(pub u64);

impl DatabaseKeyPrefixConst for EpochHistoryKey {
    const DB_PREFIX: u8 = DB_PREFIX_EPOCH_HISTORY;
    type Key = Self;
    type Value = EpochHistory;
}

#[derive(Debug, Encodable, Decodable)]
pub struct LastEpochKey;

impl DatabaseKeyPrefixConst for LastEpochKey {
    const DB_PREFIX: u8 = DB_PREFIX_LAST_EPOCH;
    type Key = Self;
    type Value = EpochHistoryKey;
}
