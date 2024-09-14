use bitcoin::{TxOut, Txid};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record};
use secp256k1::ecdsa::Signature;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::{FederationWallet, PendingTransaction, TransactionLog, UnsignedTransaction};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Deposit = 0x30,
    SpentDeposit = 0x31,
    BlockCountVote = 0x32,
    FeeRateVote = 0x33,
    TransactionLog = 0x35,
    TransactionLogIndex = 0x36,
    UnsignedTransaction = 0x37,
    Signatures = 0x38,
    PendingTransaction = 0x39,
    FederationWallet = 0x40,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct DepositKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct DepositPrefix;

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct Deposit(pub bitcoin::OutPoint, pub TxOut);

impl_db_record!(
    key = DepositKey,
    value = Deposit,
    db_prefix = DbKeyPrefix::Deposit,
);

impl_db_lookup!(key = DepositKey, query_prefix = DepositPrefix);

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct SpentDepositKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SpentDepositPrefix;

impl_db_record!(
    key = SpentDepositKey,
    value = (),
    db_prefix = DbKeyPrefix::SpentDeposit
);

impl_db_lookup!(key = SpentDepositKey, query_prefix = SpentDepositPrefix);

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct FederationWalletPrefix;

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct FederationWalletKey;

impl_db_record!(
    key = FederationWalletKey,
    value = FederationWallet,
    db_prefix = DbKeyPrefix::FederationWallet,
);

impl_db_lookup!(
    key = FederationWalletKey,
    query_prefix = FederationWalletPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct TransactionLogKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct TransactionLogPrefix;

impl_db_record!(
    key = TransactionLogKey,
    value = TransactionLog,
    db_prefix = DbKeyPrefix::TransactionLog,
);

impl_db_lookup!(key = TransactionLogKey, query_prefix = TransactionLogPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct TransactionLogIndexKey(pub fedimint_core::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct TransactionLogIndexPrefix;

impl_db_record!(
    key = TransactionLogIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::TransactionLogIndex,
);

impl_db_lookup!(
    key = TransactionLogIndexKey,
    query_prefix = TransactionLogIndexPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnsignedTransactionKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnsignedTransactionPrefix;

impl_db_record!(
    key = UnsignedTransactionKey,
    value = UnsignedTransaction,
    db_prefix = DbKeyPrefix::UnsignedTransaction,
);

impl_db_lookup!(
    key = UnsignedTransactionKey,
    query_prefix = UnsignedTransactionPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct SignaturesKey(pub Txid, pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SignaturesTxidPrefix(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SignaturesPrefix;

impl_db_record!(
    key = SignaturesKey,
    value = Vec<Signature>,
    db_prefix = DbKeyPrefix::Signatures,
);

impl_db_lookup!(key = SignaturesKey, query_prefix = SignaturesTxidPrefix);

impl_db_lookup!(key = SignaturesKey, query_prefix = SignaturesPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PendingTransactionKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransactionPrefix;

impl_db_record!(
    key = PendingTransactionKey,
    value = PendingTransaction,
    db_prefix = DbKeyPrefix::PendingTransaction,
);

impl_db_lookup!(
    key = PendingTransactionKey,
    query_prefix = PendingTransactionPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct BlockCountVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockCountVotePrefix;

impl_db_record!(
    key = BlockCountVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::BlockCountVote
);

impl_db_lookup!(key = BlockCountVoteKey, query_prefix = BlockCountVotePrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct FeeRateVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FeeRateVotePrefix;

impl_db_record!(
    key = FeeRateVoteKey,
    value = Option<u64>,
    db_prefix = DbKeyPrefix::FeeRateVote
);

impl_db_lookup!(key = FeeRateVoteKey, query_prefix = FeeRateVotePrefix);
