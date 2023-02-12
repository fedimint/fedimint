use std::fmt::Debug;

use fedimint_core::db::MODULE_GLOBAL_PREFIX;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::{SerdeSignature, SignedEpochOutcome};
use fedimint_core::impl_db_prefix_const;
use fedimint_core::{PeerId, TransactionId};
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
    key = AcceptedTransactionKey,
    value = AcceptedTransaction,
    prefix = DbKeyPrefix::AcceptedTransaction,
    key_prefix = AcceptedTransactionKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct RejectedTransactionKey(pub TransactionId);

#[derive(Debug, Encodable, Decodable)]
pub struct RejectedTransactionKeyPrefix;

impl_db_prefix_const!(
    key = RejectedTransactionKey,
    value = String,
    prefix = DbKeyPrefix::RejectedTransaction,
    key_prefix = RejectedTransactionKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct DropPeerKey(pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct DropPeerKeyPrefix;

impl_db_prefix_const!(
    key = DropPeerKey,
    value = (),
    prefix = DbKeyPrefix::DropPeer,
    key_prefix = DropPeerKeyPrefix
);

#[derive(Debug, Copy, Clone, Encodable, Decodable, Serialize)]
pub struct EpochHistoryKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct EpochHistoryKeyPrefix;

impl_db_prefix_const!(
    key = EpochHistoryKey,
    value = SignedEpochOutcome,
    prefix = DbKeyPrefix::EpochHistory,
    key_prefix = EpochHistoryKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LastEpochKey;

impl_db_prefix_const!(
    key = LastEpochKey,
    value = EpochHistoryKey,
    prefix = DbKeyPrefix::LastEpoch
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientConfigSignatureKey;

#[derive(Debug, Encodable, Decodable)]
pub struct ClientConfigSignatureKeyPrefix;

impl_db_prefix_const!(
    key = ClientConfigSignatureKey,
    value = SerdeSignature,
    prefix = DbKeyPrefix::ClientConfigSignature,
    key_prefix = ClientConfigSignatureKeyPrefix
);
