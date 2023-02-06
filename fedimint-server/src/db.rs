use std::fmt::Debug;

use fedimint_api::db::{DatabaseKeyPrefixConst, MODULE_GLOBAL_PREFIX};
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::impl_db_prefix_const;
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

#[derive(Debug, Encodable, Decodable)]
pub struct AcceptedTransactionKeyPrefix;

impl_db_prefix_const!(
    AcceptedTransactionKey,
    AcceptedTransactionKeyPrefix,
    AcceptedTransaction,
    DbKeyPrefix::AcceptedTransaction
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct RejectedTransactionKey(pub TransactionId);

#[derive(Debug, Encodable, Decodable)]
pub struct RejectedTransactionKeyPrefix;

impl_db_prefix_const!(
    RejectedTransactionKey,
    RejectedTransactionKeyPrefix,
    String,
    DbKeyPrefix::RejectedTransaction
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct DropPeerKey(pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct DropPeerKeyPrefix;

impl_db_prefix_const!(DropPeerKey, DropPeerKeyPrefix, (), DbKeyPrefix::DropPeer);

#[derive(Debug, Copy, Clone, Encodable, Decodable, Serialize)]
pub struct EpochHistoryKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct EpochHistoryKeyPrefix;

impl_db_prefix_const!(
    EpochHistoryKey,
    EpochHistoryKeyPrefix,
    SignedEpochOutcome,
    DbKeyPrefix::EpochHistory
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LastEpochKey;

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LastEpochKeyPrefix;

impl_db_prefix_const!(
    LastEpochKey,
    LastEpochKeyPrefix,
    EpochHistoryKey,
    DbKeyPrefix::LastEpoch
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientConfigSignatureKey;

#[derive(Debug, Encodable, Decodable)]
pub struct ClientConfigSignatureKeyPrefix;

impl_db_prefix_const!(
    ClientConfigSignatureKey,
    ClientConfigSignatureKeyPrefix,
    SerdeSignature,
    DbKeyPrefix::ClientConfigSignature
);
