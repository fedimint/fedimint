use std::collections::BTreeMap;

use fedimint_core::db::IWriteDatabaseTransactionOpsTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::util::SafeUrl;
use fedimint_core::{OutPoint, PeerId, impl_db_lookup, impl_db_record};
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract};
use fedimint_lnv2_common::{ContractId, LightningInputV0, LightningOutputV0};
use fedimint_server_core::migration::{
    ModuleHistoryItem, ServerModuleDbMigrationFnContext, ServerModuleDbMigrationFnContextExt,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;
use tpe::DecryptionKeyShare;

use crate::Lightning;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    BlockCountVote = 0x01,
    UnixTimeVote = 0x02,
    IncomingContract = 0x03,
    IncomingContractOutpoint = 0x04,
    OutgoingContract = 0x05,
    DecryptionKeyShare = 0x06,
    Preimage = 0x07,
    Gateway = 0x08,
    IncomingContractStreamIndex = 0x09,
    IncomingContractStream = 0x10,
    IncomingContractIndex = 0x11,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct BlockCountVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockCountVotePrefix;

impl_db_record!(
    key = BlockCountVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::BlockCountVote,
);

impl_db_lookup!(key = BlockCountVoteKey, query_prefix = BlockCountVotePrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct UnixTimeVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnixTimeVotePrefix;

impl_db_record!(
    key = UnixTimeVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::UnixTimeVote,
);

impl_db_lookup!(key = UnixTimeVoteKey, query_prefix = UnixTimeVotePrefix);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractKey(pub OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct IncomingContractPrefix;

impl_db_record!(
    key = IncomingContractKey,
    value = IncomingContract,
    db_prefix = DbKeyPrefix::IncomingContract,
    notify_on_modify = true
);

impl_db_lookup!(
    key = IncomingContractKey,
    query_prefix = IncomingContractPrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractOutpointKey(pub ContractId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct IncomingContractOutpointPrefix;

impl_db_record!(
    key = IncomingContractOutpointKey,
    value = OutPoint,
    db_prefix = DbKeyPrefix::IncomingContractOutpoint,
    notify_on_modify = true
);

impl_db_lookup!(
    key = IncomingContractOutpointKey,
    query_prefix = IncomingContractOutpointPrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct OutgoingContractKey(pub OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct OutgoingContractPrefix;

impl_db_record!(
    key = OutgoingContractKey,
    value = OutgoingContract,
    db_prefix = DbKeyPrefix::OutgoingContract,
    notify_on_modify = true
);

impl_db_lookup!(
    key = OutgoingContractKey,
    query_prefix = OutgoingContractPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct DecryptionKeyShareKey(pub OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct DecryptionKeySharePrefix;

impl_db_record!(
    key = DecryptionKeyShareKey,
    value = DecryptionKeyShare,
    db_prefix = DbKeyPrefix::DecryptionKeyShare,
    notify_on_modify = true
);

impl_db_lookup!(
    key = DecryptionKeyShareKey,
    query_prefix = DecryptionKeySharePrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PreimageKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct PreimagePrefix;

impl_db_record!(
    key = PreimageKey,
    value = [u8; 32],
    db_prefix = DbKeyPrefix::Preimage,
    notify_on_modify = true
);

impl_db_lookup!(key = PreimageKey, query_prefix = PreimagePrefix);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct GatewayKey(pub SafeUrl);

#[derive(Debug, Encodable, Decodable)]
pub struct GatewayPrefix;

impl_db_record!(
    key = GatewayKey,
    value = (),
    db_prefix = DbKeyPrefix::Gateway,
);

impl_db_lookup!(key = GatewayKey, query_prefix = GatewayPrefix);

/// Incoming contracts are indexed in three ways:
/// 1) A sequential stream mapping: `stream_index (u64)` -> `IncomingContract`
///    This enables efficient streaming reads using
///    `IncomingContractStreamPrefix(start)`.
/// 2) A global monotonically increasing index: `IncomingContractStreamIndexKey`
///    -> `u64` This stores the next stream index to be assigned and is used to
///    wait for new icoming contracts to arrive.
/// 3) A reverse lookup from `OutPoint` -> `stream_index` (via
///    `IncomingContractIndexKey`) This allows finding a specific incoming
///    contract's stream position by its `OutPoint`, while still supporting
///    sequential reads via the stream prefix. This is used to remove the
///    contract from the stream once it has been spent.
///
/// The combination allows both random access (by `OutPoint`) and ordered
/// iteration over all unspent incoming contracts (by `stream_index`).

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractStreamIndexKey;

impl_db_record!(
    key = IncomingContractStreamIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::IncomingContractStreamIndex,
    notify_on_modify = true
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractStreamKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct IncomingContractStreamPrefix(pub u64);

impl_db_record!(
    key = IncomingContractStreamKey,
    value = IncomingContract,
    db_prefix = DbKeyPrefix::IncomingContractStream,
);

impl_db_lookup!(
    key = IncomingContractStreamKey,
    query_prefix = IncomingContractStreamPrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractIndexKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct IncomingContractIndexPrefix;

impl_db_record!(
    key = IncomingContractIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::IncomingContractIndex,
);

impl_db_lookup!(
    key = IncomingContractIndexKey,
    query_prefix = IncomingContractIndexPrefix
);

pub async fn migrate_to_v1(
    mut ctx: ServerModuleDbMigrationFnContext<'_, Lightning>,
) -> Result<(), anyhow::Error> {
    let mut contracts = BTreeMap::new();
    let mut stream_index = 0;

    let mut stream = ctx.get_typed_module_history_stream().await;

    while let Some(item) = stream.next().await {
        match item {
            ModuleHistoryItem::Output(output, outpoint) => {
                if let Some(LightningOutputV0::Incoming(contract)) = output.maybe_v0_ref() {
                    contracts.insert(outpoint, (stream_index, contract.clone()));
                    stream_index += 1;
                }
            }
            ModuleHistoryItem::Input(input) => {
                if let Some(LightningInputV0::Incoming(outpoint, _)) = input.maybe_v0_ref() {
                    contracts.remove(outpoint);
                }
            }
            ModuleHistoryItem::ConsensusItem(_) => {}
        }
    }

    drop(stream);

    for (outpoint, (index, contract)) in contracts {
        ctx.dbtx()
            .insert_new_entry(&IncomingContractStreamKey(index), &contract)
            .await;

        ctx.dbtx()
            .insert_new_entry(&IncomingContractIndexKey(outpoint), &index)
            .await;
    }

    ctx.dbtx()
        .insert_new_entry(&IncomingContractStreamIndexKey, &stream_index)
        .await;

    Ok(())
}
