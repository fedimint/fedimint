use std::collections::BTreeMap;
use std::marker;
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_core::core::{DynInput, DynModuleConsensusItem, DynOutput, ModuleInstanceId};
use fedimint_core::db::{
    Database, DatabaseVersion, DbMigrationFn, DbMigrationFnContext, WriteDatabaseTransaction,
    apply_migrations_dbtx,
};
use fedimint_core::module::ModuleCommon;
use fedimint_core::util::BoxStream;
use fedimint_core::{OutPoint, apply, async_trait_maybe_send};
use futures::StreamExt as _;

use crate::ServerModule;

/// Typed history item of a module
pub enum DynModuleHistoryItem {
    ConsensusItem(DynModuleConsensusItem),
    Input(DynInput),
    Output(DynOutput, OutPoint),
}

/// Typed history item of a module
pub enum ModuleHistoryItem<M: ModuleCommon> {
    ConsensusItem(M::ConsensusItem),
    Input(M::Input),
    Output(M::Output, OutPoint),
}

/// An interface a server module db migration context needs to implement
///
/// An instance of this type is injected to server-side migrations from
/// `fedimint-server`, but users of it (and `fedimint-server-core`) do not need
/// to know the implementation.
#[apply(async_trait_maybe_send!)]
pub trait IServerDbMigrationContext {
    /// Get a stream of historical consensus items belonging to the module
    async fn get_module_history_stream<'s, 'tx>(
        &'s self,
        module_id: ModuleInstanceId,
        dbtx: &'s mut WriteDatabaseTransaction<'tx>,
    ) -> BoxStream<'s, DynModuleHistoryItem>;
}

/// A type-erased value implementing [`IServerDbMigrationContext`]
pub type DynServerDbMigrationContext = Arc<dyn IServerDbMigrationContext + Send + Sync + 'static>;

/// A module-typed wrapper over a typed-erased [`DynServerDbMigrationContext`]
///
/// This is to wrap erased [`IServerDbMigrationContext`] interfaces and
/// expose typed interfaces to the server module db migrations.
pub struct ServerModuleDbMigrationContext<M> {
    ctx: DynServerDbMigrationContext,
    module: marker::PhantomData<M>,
}

impl<M> ServerModuleDbMigrationContext<M> {
    pub(crate) fn new(ctx: DynServerDbMigrationContext) -> Self {
        Self {
            ctx,
            module: marker::PhantomData,
        }
    }

    fn ctx(&self) -> &DynServerDbMigrationContext {
        &self.ctx
    }
}

/// A type alias of a [`DbMigrationFnContext`] with inner context
/// set to module-specific-typed [`ServerModuleDbMigrationContext`]
pub type ServerModuleDbMigrationFnContext<'tx, M> =
    DbMigrationFnContext<'tx, ServerModuleDbMigrationContext<M>>;

/// An extension trait to access module-specific-typed apis of
/// [`IServerDbMigrationContext`] injected by the `fedimint-server`.
///
/// Needs to be an extension trait, as `fedimint-server-core` can't
/// implement things on general-purpose [`DbMigrationFnContext`]
#[async_trait]
pub trait ServerModuleDbMigrationFnContextExt<M>
where
    M: ServerModule,
{
    async fn get_typed_module_history_stream(
        &mut self,
    ) -> BoxStream<ModuleHistoryItem<<M as ServerModule>::Common>>;
}

#[async_trait]
impl<M> ServerModuleDbMigrationFnContextExt<M> for ServerModuleDbMigrationFnContext<'_, M>
where
    M: ServerModule + Send + Sync,
{
    async fn get_typed_module_history_stream(
        &mut self,
    ) -> BoxStream<ModuleHistoryItem<<M as ServerModule>::Common>> {
        let module_instance_id = self
            .module_instance_id()
            .expect("module_instance_id must be set");
        let (dbtx, ctx) = self.split_dbtx_ctx();

        Box::pin(
            ctx
                .ctx()
                .get_module_history_stream(
                    module_instance_id,
                    dbtx
                )
                .await
                .map(|item| match item {
                    DynModuleHistoryItem::ConsensusItem(ci) => ModuleHistoryItem::ConsensusItem(
                        ci.as_any()
                            .downcast_ref::<<<M as ServerModule>::Common as ModuleCommon>::ConsensusItem>()
                            .expect("Wrong module type")
                            .clone(),
                    ),
                    DynModuleHistoryItem::Input(input) => ModuleHistoryItem::Input(
                        input
                            .as_any()
                            .downcast_ref::<<<M as ServerModule>::Common as ModuleCommon>::Input>()
                            .expect("Wrong module type")
                            .clone(),
                    ),
                    DynModuleHistoryItem::Output(output, outpoint) => ModuleHistoryItem::Output(
                        output
                            .as_any()
                            .downcast_ref::<<<M as ServerModule>::Common as ModuleCommon>::Output>()
                            .expect("Wrong module type")
                            .clone(),
                        outpoint,
                    ),
                }),
        )
    }
}

/// A [`DbMigrationFn`] with inner-context type-specific for a given server
/// module
pub type ServerModuleDbMigrationFn<M> = DbMigrationFn<ServerModuleDbMigrationContext<M>>;

/// A [`DbMigrationFn`] with inner-context type-erased for all server modules
pub type DynServerDbMigrationFn = DbMigrationFn<DynServerDbMigrationContext>;
/// A [`DbMigrationFnContext`] with inner-context type-erased around
/// [`IServerDbMigrationContext`]
pub type ServerDbMigrationFnContext<'tx> = DbMigrationFnContext<'tx, DynServerDbMigrationContext>;

/// See [`apply_migrations_server_dbtx`]
pub async fn apply_migrations_server(
    ctx: DynServerDbMigrationContext,
    db: &Database,
    kind: String,
    migrations: BTreeMap<DatabaseVersion, DynServerDbMigrationFn>,
) -> Result<(), anyhow::Error> {
    let mut global_dbtx = db.begin_write_transaction().await;
    global_dbtx.ensure_global()?;
    apply_migrations_server_dbtx(&mut global_dbtx.to_ref_nc(), ctx, kind, migrations).await?;
    global_dbtx
        .commit_tx_result()
        .await
        .map_err(|e| anyhow::Error::msg(e.to_string()))
}

/// Applies the database migrations to a non-isolated database.
pub async fn apply_migrations_server_dbtx(
    global_dbtx: &mut WriteDatabaseTransaction<'_>,
    ctx: DynServerDbMigrationContext,
    kind: String,
    migrations: BTreeMap<DatabaseVersion, DynServerDbMigrationFn>,
) -> Result<(), anyhow::Error> {
    global_dbtx.ensure_global()?;
    apply_migrations_dbtx(global_dbtx, ctx, kind, migrations, None, None).await
}
