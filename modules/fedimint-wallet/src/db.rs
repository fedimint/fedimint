use bitcoin::{BlockHash, Txid};
use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use secp256k1::ecdsa::Signature;

use crate::{
    PegOutOutcome, PendingTransaction, RoundConsensus, SpendableUTXO, UnsignedTransaction,
};

#[repr(u8)]
#[derive(Clone)]
pub enum DbKeyPrefix {
    BlockHash = 0x30,
    Utxo = 0x31,
    RoundConsensus = 0x32,
    UnsignedTransaction = 0x34,
    PendingTransaction = 0x35,
    PegOutTxSigCi = 0x36,
    PegOutBitcoinOutPoint = 0x37,
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockHashKey(pub BlockHash);

impl DatabaseKeyPrefixConst for BlockHashKey {
    const DB_PREFIX: u8 = DbKeyPrefix::BlockHash as u8;
    type Key = Self;
    type Value = ();
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UTXOKey(pub bitcoin::OutPoint);

impl DatabaseKeyPrefixConst for UTXOKey {
    const DB_PREFIX: u8 = DbKeyPrefix::Utxo as u8;
    type Key = Self;
    type Value = SpendableUTXO;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UTXOPrefixKey;

impl DatabaseKeyPrefixConst for UTXOPrefixKey {
    const DB_PREFIX: u8 = DbKeyPrefix::Utxo as u8;
    type Key = UTXOKey;
    type Value = SpendableUTXO;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct RoundConsensusKey;

impl DatabaseKeyPrefixConst for RoundConsensusKey {
    const DB_PREFIX: u8 = DbKeyPrefix::RoundConsensus as u8;
    type Key = Self;
    type Value = RoundConsensus;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnsignedTransactionKey(pub Txid);

impl DatabaseKeyPrefixConst for UnsignedTransactionKey {
    const DB_PREFIX: u8 = DbKeyPrefix::UnsignedTransaction as u8;
    type Key = Self;
    type Value = UnsignedTransaction;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnsignedTransactionPrefixKey;

impl DatabaseKeyPrefixConst for UnsignedTransactionPrefixKey {
    const DB_PREFIX: u8 = DbKeyPrefix::UnsignedTransaction as u8;
    type Key = UnsignedTransactionKey;
    type Value = UnsignedTransaction;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransactionKey(pub Txid);

impl DatabaseKeyPrefixConst for PendingTransactionKey {
    const DB_PREFIX: u8 = DbKeyPrefix::PendingTransaction as u8;
    type Key = Self;
    type Value = PendingTransaction;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransactionPrefixKey;

impl DatabaseKeyPrefixConst for PendingTransactionPrefixKey {
    const DB_PREFIX: u8 = DbKeyPrefix::PendingTransaction as u8;
    type Key = PendingTransactionKey;
    type Value = PendingTransaction;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutTxSignatureCI(pub Txid);

impl DatabaseKeyPrefixConst for PegOutTxSignatureCI {
    const DB_PREFIX: u8 = DbKeyPrefix::PegOutTxSigCi as u8;
    type Key = Self;
    type Value = Vec<Signature>; // TODO: define newtype
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutTxSignatureCIPrefix;

impl DatabaseKeyPrefixConst for PegOutTxSignatureCIPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::PegOutTxSigCi as u8;
    type Key = PegOutTxSignatureCI;
    type Value = Vec<Signature>;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutBitcoinTransaction(pub fedimint_api::OutPoint);

impl DatabaseKeyPrefixConst for PegOutBitcoinTransaction {
    const DB_PREFIX: u8 = DbKeyPrefix::PegOutBitcoinOutPoint as u8;
    type Key = Self;
    type Value = PegOutOutcome;
}
