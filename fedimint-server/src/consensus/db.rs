use std::collections::BTreeMap;
use std::fmt::Debug;

use fedimint_core::core::{DynInput, DynModuleConsensusItem, DynOutput, ModuleInstanceId};
use fedimint_core::db::{
    DatabaseVersion, DbMigrationFnContext, IDatabaseTransactionOpsCoreTyped,
    ServerDbMigrationContext, ServerDbMigrationFn,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::ModuleCommon;
use fedimint_core::session_outcome::{AcceptedItem, SignedSessionOutcome};
use fedimint_core::util::BoxStream;
use fedimint_core::{TransactionId, apply, async_trait_maybe_send, impl_db_lookup, impl_db_record};
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

pub fn get_global_database_migrations() -> BTreeMap<DatabaseVersion, ServerDbMigrationFn> {
    BTreeMap::new()
}

pub enum ModuleHistoryItem {
    ConsensusItem(DynModuleConsensusItem),
    Input(DynInput),
    Output(DynOutput),
}

pub enum TypedModuleHistoryItem<M: ModuleCommon> {
    ConsensusItem(M::ConsensusItem),
    Input(M::Input),
    Output(M::Output),
}

#[apply(async_trait_maybe_send!)]
pub trait MigrationContextExt {
    async fn get_module_history_stream(&mut self) -> BoxStream<ModuleHistoryItem>;

    async fn get_typed_module_history_stream<M: ModuleCommon>(
        &mut self,
    ) -> BoxStream<TypedModuleHistoryItem<M>>;
}

#[apply(async_trait_maybe_send!)]
impl MigrationContextExt for DbMigrationFnContext<'_, ServerDbMigrationContext> {
    async fn get_module_history_stream(&mut self) -> BoxStream<ModuleHistoryItem> {
        let module_instance_id = self
            .module_instance_id()
            .expect("module_instance_id must be set");

        // Items of the currently ongoing session, that have already been processed. We
        // have to query them in full first and collect them into a vector so we don't
        // hold two references to the dbtx at the same time.
        let active_session_items = self
            .__global_dbtx()
            .find_by_prefix(&AcceptedItemPrefix)
            .await
            .map(|(_, item)| item)
            .collect::<Vec<_>>()
            .await;

        let stream = self
            .__global_dbtx()
            .find_by_prefix(&SignedSessionOutcomePrefix)
            .await
            // Transform the session stream into an accepted item stream
            .flat_map(|(_, signed_session_outcome): (_, SignedSessionOutcome)| {
                futures::stream::iter(signed_session_outcome.session_outcome.items)
            })
            // Append the accepted items from the current session after all the signed session items
            // have been processed
            .chain(futures::stream::iter(active_session_items))
            .flat_map(move |item| {
                let history_items = match item.item {
                    ConsensusItem::Transaction(tx) => tx
                        .inputs
                        .into_iter()
                        .filter_map(|input| {
                            (input.module_instance_id() == module_instance_id)
                                .then_some(ModuleHistoryItem::Input(input))
                        })
                        .chain(tx.outputs.into_iter().filter_map(|output| {
                            (output.module_instance_id() == module_instance_id)
                                .then_some(ModuleHistoryItem::Output(output))
                        }))
                        .collect::<Vec<_>>(),
                    ConsensusItem::Module(mci) => {
                        if mci.module_instance_id() == module_instance_id {
                            vec![ModuleHistoryItem::ConsensusItem(mci)]
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

    async fn get_typed_module_history_stream<M: ModuleCommon>(
        &mut self,
    ) -> BoxStream<TypedModuleHistoryItem<M>> {
        Box::pin(self.get_module_history_stream().await.map(|item| {
            match item {
                ModuleHistoryItem::ConsensusItem(ci) => TypedModuleHistoryItem::ConsensusItem(
                    ci.as_any()
                        .downcast_ref::<M::ConsensusItem>()
                        .expect("Wrong module type")
                        .clone(),
                ),
                ModuleHistoryItem::Input(input) => TypedModuleHistoryItem::Input(
                    input
                        .as_any()
                        .downcast_ref::<M::Input>()
                        .expect("Wrong module type")
                        .clone(),
                ),
                ModuleHistoryItem::Output(output) => TypedModuleHistoryItem::Output(
                    output
                        .as_any()
                        .downcast_ref::<M::Output>()
                        .expect("Wrong module type")
                        .clone(),
                ),
            }
        }))
    }
}
