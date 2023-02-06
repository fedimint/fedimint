use bitcoin::{BlockHash, Txid};
use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::impl_db_prefix_const;
use secp256k1::ecdsa::Signature;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::{
    PendingTransaction, RoundConsensus, SpendableUTXO, UnsignedTransaction, WalletOutputOutcome,
};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    BlockHash = 0x30,
    Utxo = 0x31,
    RoundConsensus = 0x32,
    UnsignedTransaction = 0x34,
    PendingTransaction = 0x35,
    PegOutTxSigCi = 0x36,
    PegOutBitcoinOutPoint = 0x37,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct BlockHashKey(pub BlockHash);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockHashKeyPrefix;

impl_db_prefix_const!(BlockHashKey, BlockHashKeyPrefix, (), DbKeyPrefix::BlockHash);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UTXOKey(pub bitcoin::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UTXOPrefixKey;

impl_db_prefix_const!(UTXOKey, UTXOPrefixKey, SpendableUTXO, DbKeyPrefix::Utxo);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct RoundConsensusKey;

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct RoundConsensusPrefixKey;

impl_db_prefix_const!(
    RoundConsensusKey,
    RoundConsensusPrefixKey,
    RoundConsensus,
    DbKeyPrefix::RoundConsensus
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnsignedTransactionKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnsignedTransactionPrefixKey;

impl_db_prefix_const!(
    UnsignedTransactionKey,
    UnsignedTransactionPrefixKey,
    UnsignedTransaction,
    DbKeyPrefix::UnsignedTransaction
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PendingTransactionKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransactionPrefixKey;

impl_db_prefix_const!(
    PendingTransactionKey,
    PendingTransactionPrefixKey,
    PendingTransaction,
    DbKeyPrefix::PendingTransaction
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegOutTxSignatureCI(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutTxSignatureCIPrefix;

impl_db_prefix_const!(
    PegOutTxSignatureCI,
    PegOutTxSignatureCIPrefix,
    Vec<Signature>,
    DbKeyPrefix::PegOutTxSigCi
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegOutBitcoinTransaction(pub fedimint_api::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutBitcoinTransactionPrefix;

impl_db_prefix_const!(
    PegOutBitcoinTransaction,
    PegOutBitcoinTransactionPrefix,
    WalletOutputOutcome,
    DbKeyPrefix::PegOutBitcoinOutPoint
);
