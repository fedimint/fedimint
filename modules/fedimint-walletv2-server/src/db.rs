use bitcoin::{TxOut, Txid};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, PeerId};
use secp256k1::ecdsa::Signature;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::{FederationWallet, PendingTransaction, UnsignedTransaction, WalletOutputOutcome};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    UnspentTxOutKey = 0x30,
    SpentOutPoint = 0x31,
    BlockCountVote = 0x32,
    FeeRateVote = 0x33,
    FeeRateIndex = 0x34,
    UnsignedTransaction = 0x35,
    Signatures = 0x36,
    PendingTransaction = 0x37,
    OutputOutcome = 0x38,
    FederationWallet = 0x39,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnspentTxOutKey(pub bitcoin::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnspentTxOutPrefix;

impl_db_record!(
    key = UnspentTxOutKey,
    value = TxOut,
    db_prefix = DbKeyPrefix::UnspentTxOutKey,
);

impl_db_lookup!(key = UnspentTxOutKey, query_prefix = UnspentTxOutPrefix);

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct SpentOutPointKey(pub bitcoin::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SpentOutPointPrefix;

impl_db_record!(
    key = SpentOutPointKey,
    value = (),
    db_prefix = DbKeyPrefix::SpentOutPoint
);

impl_db_lookup!(key = SpentOutPointKey, query_prefix = SpentOutPointPrefix);

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
pub struct OutputOutcomeKey(pub fedimint_core::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct OutputOutcomePrefix;

impl_db_record!(
    key = OutputOutcomeKey,
    value = WalletOutputOutcome,
    db_prefix = DbKeyPrefix::OutputOutcome,
);
impl_db_lookup!(key = OutputOutcomeKey, query_prefix = OutputOutcomePrefix);

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

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct FeeRateIndexKey;

impl_db_record!(
    key = FeeRateIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::FeeRateIndex
);
