use std::fmt::Debug;

use fedimint_api::core::MODULE_KEY_GLOBAL;
use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::{PeerId, TransactionId};
use fedimint_core::epoch::SignedEpochOutcome;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::consensus::AcceptedTransaction;
use crate::transaction::Transaction;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    ProposedTransaction = 0x01,
    AcceptedTransaction = 0x02,
    DropPeer = 0x03,
    RejectedTransaction = 0x04,
    EpochHistory = 0x05,
    LastEpoch = 0x06,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ProposedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for ProposedTransactionKey {
    const MODULE_PREFIX: u16 = MODULE_KEY_GLOBAL;
    const DB_PREFIX: u8 = DbKeyPrefix::ProposedTransaction as u8;
    type Key = Self;
    type Value = Transaction;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedTransactionKeyPrefix;

impl DatabaseKeyPrefixConst for ProposedTransactionKeyPrefix {
    const MODULE_PREFIX: u16 = MODULE_KEY_GLOBAL;
    const DB_PREFIX: u8 = DbKeyPrefix::ProposedTransaction as u8;
    type Key = ProposedTransactionKey;
    type Value = Transaction;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct AcceptedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for AcceptedTransactionKey {
    const MODULE_PREFIX: u16 = MODULE_KEY_GLOBAL;
    const DB_PREFIX: u8 = DbKeyPrefix::AcceptedTransaction as u8;
    type Key = Self;
    type Value = AcceptedTransaction;
}

#[derive(Debug, Encodable, Decodable)]
pub struct AcceptedTransactionKeyPrefix;

impl DatabaseKeyPrefixConst for AcceptedTransactionKeyPrefix {
    const MODULE_PREFIX: u16 = MODULE_KEY_GLOBAL;
    const DB_PREFIX: u8 = DbKeyPrefix::AcceptedTransaction as u8;
    type Key = AcceptedTransactionKey;
    type Value = AcceptedTransaction;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct RejectedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for RejectedTransactionKey {
    const MODULE_PREFIX: u16 = MODULE_KEY_GLOBAL;
    const DB_PREFIX: u8 = DbKeyPrefix::RejectedTransaction as u8;
    type Key = Self;
    type Value = String;
}

#[derive(Debug, Encodable, Decodable)]
pub struct RejectedTransactionKeyPrefix;

impl DatabaseKeyPrefixConst for RejectedTransactionKeyPrefix {
    const MODULE_PREFIX: u16 = MODULE_KEY_GLOBAL;
    const DB_PREFIX: u8 = DbKeyPrefix::RejectedTransaction as u8;
    type Key = RejectedTransactionKey;
    type Value = String;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct DropPeerKey(pub PeerId);

impl DatabaseKeyPrefixConst for DropPeerKey {
    const MODULE_PREFIX: u16 = MODULE_KEY_GLOBAL;
    const DB_PREFIX: u8 = DbKeyPrefix::DropPeer as u8;
    type Key = Self;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct DropPeerKeyPrefix;

impl DatabaseKeyPrefixConst for DropPeerKeyPrefix {
    const MODULE_PREFIX: u16 = MODULE_KEY_GLOBAL;
    const DB_PREFIX: u8 = DbKeyPrefix::DropPeer as u8;
    type Key = DropPeerKey;
    type Value = ();
}

#[derive(Debug, Copy, Clone, Encodable, Decodable, Serialize)]
pub struct EpochHistoryKey(pub u64);

impl DatabaseKeyPrefixConst for EpochHistoryKey {
    const MODULE_PREFIX: u16 = MODULE_KEY_GLOBAL;
    const DB_PREFIX: u8 = DbKeyPrefix::EpochHistory as u8;
    type Key = Self;
    type Value = SignedEpochOutcome;
}

#[derive(Debug, Encodable, Decodable)]
pub struct EpochHistoryKeyPrefix;

impl DatabaseKeyPrefixConst for EpochHistoryKeyPrefix {
    const MODULE_PREFIX: u16 = MODULE_KEY_GLOBAL;
    const DB_PREFIX: u8 = DbKeyPrefix::EpochHistory as u8;
    type Key = EpochHistoryKey;
    type Value = SignedEpochOutcome;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LastEpochKey;

impl DatabaseKeyPrefixConst for LastEpochKey {
    const MODULE_PREFIX: u16 = MODULE_KEY_GLOBAL;
    const DB_PREFIX: u8 = DbKeyPrefix::LastEpoch as u8;
    type Key = Self;
    type Value = EpochHistoryKey;
}
