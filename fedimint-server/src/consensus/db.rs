use std::collections::BTreeMap;
use std::fmt::Debug;

use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    DatabaseVersion, IReadDatabaseTransactionOpsTyped, WriteDatabaseTransaction,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::session_outcome::{AcceptedItem, SignedSessionOutcome};
use fedimint_core::util::BoxStream;
use fedimint_core::{
    OutPoint, TransactionId, apply, async_trait_maybe_send, impl_db_lookup, impl_db_record,
};
use fedimint_server_core::migration::{
    DynModuleHistoryItem, DynServerDbMigrationFn, IServerDbMigrationContext,
};
use futures::StreamExt;
use serde::Serialize;

use crate::db::DbKeyPrefix;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct AcceptedItemKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct AcceptedItemPrefix;

impl_db_record!(
    key = AcceptedItemKey,
    value = AcceptedItem,
    db_prefix = DbKeyPrefix::AcceptedItem,
    notify_on_modify = false,
);
impl_db_lookup!(key = AcceptedItemKey, query_prefix = AcceptedItemPrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct AcceptedTransactionKey(pub TransactionId);

#[derive(Debug, Encodable, Decodable)]
pub struct AcceptedTransactionKeyPrefix;

impl_db_record!(
    key = AcceptedTransactionKey,
    value = Vec<ModuleInstanceId>,
    db_prefix = DbKeyPrefix::AcceptedTransaction,
    notify_on_modify = true,
);
impl_db_lookup!(
    key = AcceptedTransactionKey,
    query_prefix = AcceptedTransactionKeyPrefix
);

#[derive(Debug, Encodable, Decodable)]
pub struct SignedSessionOutcomeKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct SignedSessionOutcomePrefix;

impl_db_record!(
    key = SignedSessionOutcomeKey,
    value = SignedSessionOutcome,
    db_prefix = DbKeyPrefix::SignedSessionOutcome,
    notify_on_modify = true,
);
impl_db_lookup!(
    key = SignedSessionOutcomeKey,
    query_prefix = SignedSessionOutcomePrefix
);

#[derive(Debug, Encodable, Decodable)]
pub struct AlephUnitsKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct AlephUnitsPrefix;

impl_db_record!(
    key = AlephUnitsKey,
    value = Vec<u8>,
    db_prefix = DbKeyPrefix::AlephUnits,
    notify_on_modify = false,
);
impl_db_lookup!(key = AlephUnitsKey, query_prefix = AlephUnitsPrefix);

pub fn get_global_database_migrations() -> BTreeMap<DatabaseVersion, DynServerDbMigrationFn> {
    BTreeMap::new()
}

/// A concrete implementation of [`IServerDbMigrationContext`] APIs
/// available for server-module db migrations.
pub struct ServerDbMigrationContext;

#[apply(async_trait_maybe_send!)]
impl IServerDbMigrationContext for ServerDbMigrationContext {
    async fn get_module_history_stream<'s, 'tx>(
        &'s self,
        module_instance_id: ModuleInstanceId,
        dbtx: &'s mut WriteDatabaseTransaction<'tx>,
    ) -> BoxStream<'s, DynModuleHistoryItem> {
        dbtx.ensure_global().expect("Dbtx must be global");

        // Items of the currently ongoing session, that have already been processed. We
        // have to query them in full first and collect them into a vector so we don't
        // hold two references to the dbtx at the same time.
        let active_session_items = dbtx
            .find_by_prefix(&AcceptedItemPrefix)
            .await
            .map(|(_, item)| item)
            .collect::<Vec<_>>()
            .await;

        let stream =
            dbtx.find_by_prefix(&SignedSessionOutcomePrefix)
                .await
                // Transform the session stream into an accepted item stream
                .flat_map(|(_, signed_session_outcome): (_, SignedSessionOutcome)| {
                    futures::stream::iter(signed_session_outcome.session_outcome.items)
                })
                // Append the accepted items from the current session after all the signed session
                // items have been processed
                .chain(futures::stream::iter(active_session_items))
                .flat_map(move |item| {
                    let history_items =
                        match item.item {
                            ConsensusItem::Transaction(tx) => {
                                let txid = tx.tx_hash();
                                let input_items = tx.inputs.into_iter().filter_map(|input| {
                                    (input.module_instance_id() == module_instance_id)
                                        .then_some(DynModuleHistoryItem::Input(input))
                                });

                                let output_items = tx.outputs.into_iter().zip(0..).filter_map(
                                    |(output, out_idx)| {
                                        (output.module_instance_id() == module_instance_id)
                                            .then_some(DynModuleHistoryItem::Output(
                                                output,
                                                OutPoint { txid, out_idx },
                                            ))
                                    },
                                );

                                input_items.chain(output_items).collect::<Vec<_>>()
                            }
                            ConsensusItem::Module(mci) => {
                                if mci.module_instance_id() == module_instance_id {
                                    vec![DynModuleHistoryItem::ConsensusItem(mci)]
                                } else {
                                    vec![]
                                }
                            }
                            ConsensusItem::Default { .. } => {
                                unreachable!("We never save unknown CIs on the server side")
                            }
                        };
                    futures::stream::iter(history_items)
                });

        Box::pin(stream)
    }
}
