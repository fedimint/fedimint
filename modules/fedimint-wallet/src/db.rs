use bitcoin::{BlockHash, Txid};
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

impl_db_prefix_const!(
    key = BlockHashKey,
    value = (),
    prefix = DbKeyPrefix::BlockHash,
    key_prefix = BlockHashKeyPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UTXOKey(pub bitcoin::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UTXOPrefixKey;

impl_db_prefix_const!(
    key = UTXOKey,
    value = SpendableUTXO,
    prefix = DbKeyPrefix::Utxo,
    key_prefix = UTXOPrefixKey
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct RoundConsensusKey;

impl_db_prefix_const!(
    key = RoundConsensusKey,
    value = RoundConsensus,
    prefix = DbKeyPrefix::RoundConsensus,
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnsignedTransactionKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnsignedTransactionPrefixKey;

impl_db_prefix_const!(
    key = UnsignedTransactionKey,
    value = UnsignedTransaction,
    prefix = DbKeyPrefix::UnsignedTransaction,
    key_prefix = UnsignedTransactionPrefixKey
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PendingTransactionKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransactionPrefixKey;

impl_db_prefix_const!(
    key = PendingTransactionKey,
    value = PendingTransaction,
    prefix = DbKeyPrefix::PendingTransaction,
    key_prefix = PendingTransactionPrefixKey
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegOutTxSignatureCI(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutTxSignatureCIPrefix;

impl_db_prefix_const!(
    key = PegOutTxSignatureCI,
    value = Vec<Signature>,
    prefix = DbKeyPrefix::PegOutTxSigCi,
    key_prefix = PegOutTxSignatureCIPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegOutBitcoinTransaction(pub fedimint_api::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutBitcoinTransactionPrefix;

impl_db_prefix_const!(
    key = PegOutBitcoinTransaction,
    value = WalletOutputOutcome,
    prefix = DbKeyPrefix::PegOutBitcoinOutPoint,
    key_prefix = PegOutBitcoinTransactionPrefix
);
