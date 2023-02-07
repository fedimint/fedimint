use std::fmt::Debug;

use fedimint_api::db::{DatabaseKeyPrefixConst, MODULE_GLOBAL_PREFIX};
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::{PeerId, TransactionId};
use fedimint_core::epoch::{SerdeSignature, SignedEpochOutcome};
use serde::Serialize;
use strum_macros::EnumIter;

use crate::consensus::AcceptedTransaction;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    AcceptedTransaction = 0x02,
    DropPeer = 0x03,
    RejectedTransaction = 0x04,
    EpochHistory = 0x05,
    LastEpoch = 0x06,
    ClientConfigSignature = 0x07,
    Module = MODULE_GLOBAL_PREFIX,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct AcceptedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for AcceptedTransactionKey {
    const DB_PREFIX: u8 = DbKeyPrefix::AcceptedTransaction as u8;
    type Key = Self;
    type Value = AcceptedTransaction;
}

#[derive(Debug, Encodable, Decodable)]
pub struct AcceptedTransactionKeyPrefix;

impl DatabaseKeyPrefixConst for AcceptedTransactionKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::AcceptedTransaction as u8;
    type Key = AcceptedTransactionKey;
    type Value = AcceptedTransaction;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct RejectedTransactionKey(pub TransactionId);

impl DatabaseKeyPrefixConst for RejectedTransactionKey {
    const DB_PREFIX: u8 = DbKeyPrefix::RejectedTransaction as u8;
    type Key = Self;
    type Value = String;
}

#[derive(Debug, Encodable, Decodable)]
pub struct RejectedTransactionKeyPrefix;

impl DatabaseKeyPrefixConst for RejectedTransactionKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::RejectedTransaction as u8;
    type Key = RejectedTransactionKey;
    type Value = String;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
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

#[derive(Debug, Copy, Clone, Encodable, Decodable, Serialize)]
pub struct EpochHistoryKey(pub u64);

impl DatabaseKeyPrefixConst for EpochHistoryKey {
    const DB_PREFIX: u8 = DbKeyPrefix::EpochHistory as u8;
    type Key = Self;
    type Value = SignedEpochOutcome;
}

#[derive(Debug, Encodable, Decodable)]
pub struct EpochHistoryKeyPrefix;

impl DatabaseKeyPrefixConst for EpochHistoryKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::EpochHistory as u8;
    type Key = EpochHistoryKey;
    type Value = SignedEpochOutcome;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LastEpochKey;

impl DatabaseKeyPrefixConst for LastEpochKey {
    const DB_PREFIX: u8 = DbKeyPrefix::LastEpoch as u8;
    type Key = Self;
    type Value = EpochHistoryKey;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientConfigSignatureKey;

impl DatabaseKeyPrefixConst for ClientConfigSignatureKey {
    const DB_PREFIX: u8 = DbKeyPrefix::ClientConfigSignature as u8;
    type Key = Self;
    type Value = SerdeSignature;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ClientConfigSignatureKeyPrefix;

impl DatabaseKeyPrefixConst for ClientConfigSignatureKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::ClientConfigSignature as u8;
    type Key = ClientConfigSignatureKey;
    type Value = SerdeSignature;
}
