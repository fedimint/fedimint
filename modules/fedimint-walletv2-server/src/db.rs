use bitcoin::{TxOut, Txid};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record};
use fedimint_walletv2_common::TxInfo;
use secp256k1::schnorr::Signature;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::{FederationTx, FederationWallet};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Output = 0x30,
    SpentOutput = 0x31,
    BlockCountVote = 0x32,
    FeeRateVote = 0x33,
    TxLog = 0x34,
    TxInfoIndex = 0x35,
    UnsignedTx = 0x36,
    Signatures = 0x37,
    UnconfirmedTx = 0x38,
    FederationWallet = 0x39,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct OutputKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct OutputPrefix;

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct Output(pub bitcoin::OutPoint, pub TxOut);

impl_db_record!(
    key = OutputKey,
    value = Output,
    db_prefix = DbKeyPrefix::Output,
);

impl_db_lookup!(key = OutputKey, query_prefix = OutputPrefix);

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct SpentOutputKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SpentOutputPrefix;

impl_db_record!(
    key = SpentOutputKey,
    value = (),
    db_prefix = DbKeyPrefix::SpentOutput
);

impl_db_lookup!(key = SpentOutputKey, query_prefix = SpentOutputPrefix);

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
pub struct TxInfoKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct TxInfoPrefix;

impl_db_record!(
    key = TxInfoKey,
    value = TxInfo,
    db_prefix = DbKeyPrefix::TxLog,
);

impl_db_lookup!(key = TxInfoKey, query_prefix = TxInfoPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct TxInfoIndexKey(pub fedimint_core::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct TxInfoIndexPrefix;

impl_db_record!(
    key = TxInfoIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::TxInfoIndex,
);

impl_db_lookup!(key = TxInfoIndexKey, query_prefix = TxInfoIndexPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnsignedTxKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnsignedTxPrefix;

impl_db_record!(
    key = UnsignedTxKey,
    value = FederationTx,
    db_prefix = DbKeyPrefix::UnsignedTx,
);

impl_db_lookup!(key = UnsignedTxKey, query_prefix = UnsignedTxPrefix);

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
pub struct UnconfirmedTxKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnconfirmedTxPrefix;

impl_db_record!(
    key = UnconfirmedTxKey,
    value = FederationTx,
    db_prefix = DbKeyPrefix::UnconfirmedTx,
);

impl_db_lookup!(key = UnconfirmedTxKey, query_prefix = UnconfirmedTxPrefix);

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
