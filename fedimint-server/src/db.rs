use std::fmt::Debug;

use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::{PeerId, TransactionId};
use fedimint_core::epoch::EpochHistory;

use crate::consensus::AcceptedTransaction;
use crate::transaction::Transaction;

#[repr(u8)]
#[derive(Clone)]
pub enum DbKeyPrefix {
    ProposedTransaction = 0x01,
    AcceptedTransaction = 0x02,
    DropPeer = 0x03,
    RejectedTransaction = 0x04,
    EpochHistory = 0x05,
    LastEpoch = 0x06,
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for ProposedTransactionKey {
    const DB_PREFIX: u8 = DbKeyPrefix::ProposedTransaction as u8;
    type Key = Self;
    type Value = Transaction;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedTransactionKeyPrefix;

impl DatabaseKeyPrefixConst for ProposedTransactionKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::ProposedTransaction as u8;
    type Key = ProposedTransactionKey;
    type Value = Transaction;
}

#[derive(Debug, Encodable, Decodable)]
pub struct AcceptedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for AcceptedTransactionKey {
    const DB_PREFIX: u8 = DbKeyPrefix::AcceptedTransaction as u8;
    type Key = Self;
    type Value = AcceptedTransaction;
}

#[derive(Debug, Encodable, Decodable)]
pub struct RejectedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for RejectedTransactionKey {
    const DB_PREFIX: u8 = DbKeyPrefix::RejectedTransaction as u8;
    type Key = Self;
    type Value = String;
}

#[derive(Debug, Encodable, Decodable)]
pub struct DropPeerKey(pub PeerId);

impl DatabaseKeyPrefixConst for DropPeerKey {
    const DB_PREFIX: u8 = DbKeyPrefix::DropPeer as u8;
    type Key = Self;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct DropPeerKeyPrefix;

impl DatabaseKeyPrefixConst for DropPeerKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::DropPeer as u8;
    type Key = DropPeerKey;
    type Value = ();
}

#[derive(Debug, Copy, Clone, Encodable, Decodable)]
pub struct EpochHistoryKey(pub u64);

impl DatabaseKeyPrefixConst for EpochHistoryKey {
    const DB_PREFIX: u8 = DbKeyPrefix::EpochHistory as u8;
    type Key = Self;
    type Value = EpochHistory;
}

#[derive(Debug, Encodable, Decodable)]
pub struct LastEpochKey;

impl DatabaseKeyPrefixConst for LastEpochKey {
    const DB_PREFIX: u8 = DbKeyPrefix::LastEpoch as u8;
    type Key = Self;
    type Value = EpochHistoryKey;
}
