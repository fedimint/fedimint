use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::{BlockHash, OutPoint, TxOut, Txid};
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record};
use fedimint_server_core::migration::{
    ModuleHistoryItem, ServerModuleDbMigrationFnContext, ServerModuleDbMigrationFnContextExt as _,
};
use futures::StreamExt;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::{PendingTransaction, SpendableUTXO, UnsignedTransaction, Wallet, WalletOutputOutcome};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    BlockHash = 0x30,
    Utxo = 0x31,
    BlockCountVote = 0x32,
    FeeRateVote = 0x33,
    UnsignedTransaction = 0x34,
    PendingTransaction = 0x35,
    PegOutTxSigCi = 0x36,
    PegOutBitcoinOutPoint = 0x37,
    PegOutNonce = 0x38,
    ClaimedPegInOutpoint = 0x39,
    ConsensusVersionVote = 0x40,
    UnspentTxOut = 0x41,
    ConsensusVersionVotingActivation = 0x42,
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

impl_db_record!(
    key = BlockHashKey,
    value = (),
    db_prefix = DbKeyPrefix::BlockHash,
);
impl_db_lookup!(key = BlockHashKey, query_prefix = BlockHashKeyPrefix);

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct UTXOKey(pub bitcoin::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UTXOPrefixKey;

impl_db_record!(
    key = UTXOKey,
    value = SpendableUTXO,
    db_prefix = DbKeyPrefix::Utxo,
);
impl_db_lookup!(key = UTXOKey, query_prefix = UTXOPrefixKey);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnsignedTransactionKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnsignedTransactionPrefixKey;

impl_db_record!(
    key = UnsignedTransactionKey,
    value = UnsignedTransaction,
    db_prefix = DbKeyPrefix::UnsignedTransaction,
);
impl_db_lookup!(
    key = UnsignedTransactionKey,
    query_prefix = UnsignedTransactionPrefixKey
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PendingTransactionKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransactionPrefixKey;

impl_db_record!(
    key = PendingTransactionKey,
    value = PendingTransaction,
    db_prefix = DbKeyPrefix::PendingTransaction,
);
impl_db_lookup!(
    key = PendingTransactionKey,
    query_prefix = PendingTransactionPrefixKey
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegOutTxSignatureCI(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutTxSignatureCIPrefix;

impl_db_record!(
    key = PegOutTxSignatureCI,
    value = Vec<Signature>,
    db_prefix = DbKeyPrefix::PegOutTxSigCi,
);
impl_db_lookup!(
    key = PegOutTxSignatureCI,
    query_prefix = PegOutTxSignatureCIPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegOutBitcoinTransaction(pub fedimint_core::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutBitcoinTransactionPrefix;

impl_db_record!(
    key = PegOutBitcoinTransaction,
    value = WalletOutputOutcome,
    db_prefix = DbKeyPrefix::PegOutBitcoinOutPoint,
);

impl_db_lookup!(
    key = PegOutBitcoinTransaction,
    query_prefix = PegOutBitcoinTransactionPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct BlockCountVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockCountVotePrefix;

impl_db_record!(
    key = BlockCountVoteKey,
    value = u32,
    db_prefix = DbKeyPrefix::BlockCountVote
);

impl_db_lookup!(key = BlockCountVoteKey, query_prefix = BlockCountVotePrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct FeeRateVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FeeRateVotePrefix;

impl_db_record!(
    key = FeeRateVoteKey,
    value = fedimint_core::Feerate,
    db_prefix = DbKeyPrefix::FeeRateVote
);

impl_db_lookup!(key = FeeRateVoteKey, query_prefix = FeeRateVotePrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ConsensusVersionVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ConsensusVersionVotePrefix;

impl_db_record!(
    key = ConsensusVersionVoteKey,
    value = ModuleConsensusVersion,
    db_prefix = DbKeyPrefix::ConsensusVersionVote
);

impl_db_lookup!(
    key = ConsensusVersionVoteKey,
    query_prefix = ConsensusVersionVotePrefix
);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutNonceKey;

impl_db_record!(
    key = PegOutNonceKey,
    value = u64,
    db_prefix = DbKeyPrefix::PegOutNonce
);

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct ClaimedPegInOutpointKey(pub OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ClaimedPegInOutpointPrefixKey;

impl_db_record!(
    key = ClaimedPegInOutpointKey,
    value = (),
    db_prefix = DbKeyPrefix::ClaimedPegInOutpoint,
);
impl_db_lookup!(
    key = ClaimedPegInOutpointKey,
    query_prefix = ClaimedPegInOutpointPrefixKey
);

/// Migrate to v1, backfilling all previously pegged-in outpoints
pub async fn migrate_to_v1(
    mut ctx: ServerModuleDbMigrationFnContext<'_, Wallet>,
) -> Result<(), anyhow::Error> {
    let outpoints = ctx
        .get_typed_module_history_stream()
        .await
        .filter_map(|item| async {
            match item {
                ModuleHistoryItem::Input(input) => {
                    let outpoint = input
                        .maybe_v0_ref()
                        .expect("can only support V0 wallet inputs")
                        .0
                        .outpoint();

                    Some(outpoint)
                }
                ModuleHistoryItem::Output(_) | ModuleHistoryItem::ConsensusItem(_) => None,
            }
        })
        .collect::<Vec<_>>()
        .await;

    let mut dbtx = ctx.dbtx();
    for outpoint in outpoints {
        dbtx.insert_new_entry(&ClaimedPegInOutpointKey(outpoint), &())
            .await;
    }

    Ok(())
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnspentTxOutKey(pub bitcoin::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnspentTxOutPrefix;

impl_db_record!(
    key = UnspentTxOutKey,
    value = TxOut,
    db_prefix = DbKeyPrefix::UnspentTxOut,
);
impl_db_lookup!(key = UnspentTxOutKey, query_prefix = UnspentTxOutPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ConsensusVersionVotingActivationKey;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ConsensusVersionVotingActivationPrefix;

impl_db_record!(
    key = ConsensusVersionVotingActivationKey,
    value = (),
    db_prefix = DbKeyPrefix::ConsensusVersionVotingActivation,
);
impl_db_lookup!(
    key = ConsensusVersionVotingActivationKey,
    query_prefix = ConsensusVersionVotingActivationPrefix
);
