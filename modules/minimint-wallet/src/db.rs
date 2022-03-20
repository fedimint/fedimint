use bitcoin::{BlockHash, OutPoint, Transaction, Txid};
use minimint_api::db::DatabaseKeyPrefixConst;
use minimint_api::encoding::{Decodable, Encodable};

const DB_PREFIX_BLOCK_HASH: u8 = 0x30;
const DB_PREFIX_UTXO: u8 = 0x31;
const DB_PREFIX_ROUND_CONSENSUS: u8 = 0x32;
const DB_PREFIX_PEDNING_PEGOUT: u8 = 0x33;
const DB_PREFIX_UNSIGNED_TRANSACTION: u8 = 0x34;
const DB_PREFIX_PENDING_TRANSACTION: u8 = 0x35;
const DB_PREFIX_PEG_OUT_TX_SIG_CI: u8 = 0x36;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockHashKey(pub BlockHash);

impl DatabaseKeyPrefixConst for BlockHashKey {
    const DB_PREFIX: u8 = DB_PREFIX_BLOCK_HASH;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UTXOKey(pub OutPoint);

impl DatabaseKeyPrefixConst for UTXOKey {
    const DB_PREFIX: u8 = DB_PREFIX_UTXO;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UTXOPrefixKey;

impl DatabaseKeyPrefixConst for UTXOPrefixKey {
    const DB_PREFIX: u8 = DB_PREFIX_UTXO;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct RoundConsensusKey;

impl DatabaseKeyPrefixConst for RoundConsensusKey {
    const DB_PREFIX: u8 = DB_PREFIX_ROUND_CONSENSUS;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingPegOutKey(pub minimint_api::OutPoint);

impl DatabaseKeyPrefixConst for PendingPegOutKey {
    const DB_PREFIX: u8 = DB_PREFIX_PEDNING_PEGOUT;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingPegOutPrefixKey;

impl DatabaseKeyPrefixConst for PendingPegOutPrefixKey {
    const DB_PREFIX: u8 = DB_PREFIX_PEDNING_PEGOUT;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnsignedTransactionKey(pub Txid);

impl DatabaseKeyPrefixConst for UnsignedTransactionKey {
    const DB_PREFIX: u8 = DB_PREFIX_UNSIGNED_TRANSACTION;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransactionKey(pub Txid);

impl DatabaseKeyPrefixConst for PendingTransactionKey {
    const DB_PREFIX: u8 = DB_PREFIX_PENDING_TRANSACTION;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransactionPrefixKey;

impl DatabaseKeyPrefixConst for PendingTransactionPrefixKey {
    const DB_PREFIX: u8 = DB_PREFIX_PENDING_TRANSACTION;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutTxSignatureCI(pub Txid);

impl DatabaseKeyPrefixConst for PegOutTxSignatureCI {
    const DB_PREFIX: u8 = DB_PREFIX_PEG_OUT_TX_SIG_CI;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutTxSignatureCIPrefix;

impl DatabaseKeyPrefixConst for PegOutTxSignatureCIPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_PEG_OUT_TX_SIG_CI;
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransaction {
    pub tx: Transaction,
    pub tweak: [u8; 32],
}
