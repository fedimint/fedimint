use std::fmt::Debug;
use std::marker;
use std::sync::Arc;

use fedimint_core::api::{DynGlobalApi, DynModuleApi};
use fedimint_core::config::{ClientModuleConfig, FederationId, ModuleInitRegistry};
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::db::Database;
use fedimint_core::module::{
    ApiVersion, CommonModuleInit, IDynCommonModuleInit, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, dyn_newtype_define};
use fedimint_derive_secret::DerivableSecret;
use tokio::sync::watch;
use tracing::warn;

use super::recovery::{DynModuleBackup, RecoveryProgress};
use super::{ClientContext, FinalClient};
use crate::module::{ClientModule, DynClientModule};
use crate::sm::{ModuleNotifier, Notifier};
use crate::DynGlobalClientContext;

pub type ClientModuleInitRegistry = ModuleInitRegistry<DynClientModuleInit>;

pub struct ClientModuleInitArgs<C>
where
    C: ClientModuleInit,
{
    federation_id: FederationId,
    cfg: <<C as ModuleInit>::Common as CommonModuleInit>::ClientConfig,
    db: Database,
    api_version: ApiVersion,
    module_root_secret: DerivableSecret,
    notifier: ModuleNotifier<
        DynGlobalClientContext,
        <<C as ClientModuleInit>::Module as ClientModule>::States,
    >,
    api: DynGlobalApi,
    module_api: DynModuleApi,
    context: ClientContext<<C as ClientModuleInit>::Module>,
}

impl<C> ClientModuleInitArgs<C>
where
    C: ClientModuleInit,
{
    pub fn federation_id(&self) -> &FederationId {
        &self.federation_id
    }

    pub fn cfg(&self) -> &<<C as ModuleInit>::Common as CommonModuleInit>::ClientConfig {
        &self.cfg
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn api_version(&self) -> &ApiVersion {
        &self.api_version
    }

    pub fn module_root_secret(&self) -> &DerivableSecret {
        &self.module_root_secret
    }

    pub fn notifier(
        &self,
    ) -> &ModuleNotifier<
        DynGlobalClientContext,
        <<C as ClientModuleInit>::Module as ClientModule>::States,
    > {
        &self.notifier
    }

    pub fn api(&self) -> &DynGlobalApi {
        &self.api
    }

    pub fn module_api(&self) -> &DynModuleApi {
        &self.module_api
    }

    /// Get the [`ClientContext`] for later use
    ///
    /// Notably `ClientContext` can not be used during `ClientModuleInit::init`,
    /// as the outer context is not yet complete. But it can be stored to be
    /// used in the methods of [`ClientModule`], at which point it will be
    /// ready.
    pub fn context(&self) -> ClientContext<<C as ClientModuleInit>::Module> {
        self.context.clone()
    }
}

// TODO: remove
#[allow(dead_code)]
pub struct ClientModuleRecoverArgs<C>
where
    C: ClientModuleInit,
{
    federation_id: FederationId,
    cfg: <<C as ModuleInit>::Common as CommonModuleInit>::ClientConfig,
    db: Database,
    api_version: ApiVersion,
    module_root_secret: DerivableSecret,
    notifier: ModuleNotifier<
        DynGlobalClientContext,
        <<C as ClientModuleInit>::Module as ClientModule>::States,
    >,
    api: DynGlobalApi,
    module_api: DynModuleApi,
    context: ClientContext<<C as ClientModuleInit>::Module>,
    progress_tx: tokio::sync::watch::Sender<RecoveryProgress>,
}

impl<C> ClientModuleRecoverArgs<C>
where
    C: ClientModuleInit,
{
    pub fn federation_id(&self) -> &FederationId {
        &self.federation_id
    }

    pub fn cfg(&self) -> &<<C as ModuleInit>::Common as CommonModuleInit>::ClientConfig {
        &self.cfg
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn api_version(&self) -> &ApiVersion {
        &self.api_version
    }

    pub fn module_root_secret(&self) -> &DerivableSecret {
        &self.module_root_secret
    }

    pub fn notifier(
        &self,
    ) -> &ModuleNotifier<
        DynGlobalClientContext,
        <<C as ClientModuleInit>::Module as ClientModule>::States,
    > {
        &self.notifier
    }

    pub fn api(&self) -> &DynGlobalApi {
        &self.api
    }

    pub fn module_api(&self) -> &DynModuleApi {
        &self.module_api
    }

    /// Get the [`ClientContext`]
    ///
    /// Notably `ClientContext`, unlike [`ClientModuleInitArgs::context`],
    /// the client context is guaranteed to be usable immediately.
    pub fn context(&self) -> ClientContext<<C as ClientModuleInit>::Module> {
        self.context.clone()
    }

    pub async fn update_recovery_progress(&self, progress: RecoveryProgress) {
        if progress.is_done() {
            // Recovery is complete when the recovery function finishes. To avoid
            // confusing any downstream code, we never send completed process.
            warn!("Module trying to send a completed recovery progress. Ignoring");
        } else if progress.is_none() {
            // Recovery starts with "none" none progress. To avoid
            // confusing any downstream code, we never send none process afterwards.
            warn!("Module trying to send a none recovery progress. Ignoring");
        } else if self.progress_tx.send(progress).is_err() {
            warn!("Module trying to send a recovery progress but nothing is listening");
        }
    }
}

#[apply(async_trait_maybe_send!)]
pub trait ClientModuleInit: ModuleInit + Sized {
    type Module: ClientModule;

    /// Api versions of the corresponding server side module's API
    /// that this client module implementation can use.
    fn supported_api_versions(&self) -> MultiApiVersion;

    /// Recover the state of the client module, optionally from an existing
    /// snapshot.
    ///
    /// If `Err` is returned, the higher level client/application might try
    /// again at a different time (client restarted, code version changed, etc.)
    async fn recover(
        &self,
        _args: &ClientModuleRecoverArgs<Self>,
        _snapshot: Option<&<Self::Module as ClientModule>::Backup>,
    ) -> anyhow::Result<()> {
        warn!(
            kind = %<Self::Module as ClientModule>::kind(),
            "Module does not support recovery, completing without doing anything"
        );
        Ok(())
    }

    /// Initialize a [`ClientModule`] instance from its config
    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module>;
}

#[apply(async_trait_maybe_send!)]
pub trait IClientModuleInit: IDynCommonModuleInit + Debug + MaybeSend + MaybeSync {
    fn decoder(&self) -> Decoder;

    fn module_kind(&self) -> ModuleKind;

    fn as_common(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static);

    /// See [`ClientModuleInit::supported_api_versions`]
    fn supported_api_versions(&self) -> MultiApiVersion;

    #[allow(clippy::too_many_arguments)]
    async fn recover(
        &self,
        final_client: FinalClient,
        federation_id: FederationId,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        notifier: Notifier<DynGlobalClientContext>,
        api: DynGlobalApi,
        snapshot: Option<&DynModuleBackup>,
        progress_tx: watch::Sender<RecoveryProgress>,
    ) -> anyhow::Result<()>;

    #[allow(clippy::too_many_arguments)]
    async fn init(
        &self,
        final_client: FinalClient,
        federation_id: FederationId,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        notifier: Notifier<DynGlobalClientContext>,
        api: DynGlobalApi,
    ) -> anyhow::Result<DynClientModule>;
}

#[apply(async_trait_maybe_send!)]
impl<T> IClientModuleInit for T
where
    T: ClientModuleInit + 'static + MaybeSend + Sync,
{
    fn decoder(&self) -> Decoder {
        T::Module::decoder()
    }

    fn module_kind(&self) -> ModuleKind {
        <Self as ModuleInit>::Common::KIND
    }

    fn as_common(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static) {
        self
    }

    fn supported_api_versions(&self) -> MultiApiVersion {
        <Self as ClientModuleInit>::supported_api_versions(self)
    }

    async fn recover(
        &self,
        final_client: FinalClient,
        federation_id: FederationId,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        // TODO: make dyn type for notifier
        notifier: Notifier<DynGlobalClientContext>,
        api: DynGlobalApi,
        snapshot: Option<&DynModuleBackup>,
        progress_tx: watch::Sender<RecoveryProgress>,
    ) -> anyhow::Result<()> {
        let typed_cfg: &<<T as fedimint_core::module::ModuleInit>::Common as CommonModuleInit>::ClientConfig = cfg.cast()?;
        let snapshot: Option<&<<Self as ClientModuleInit>::Module as ClientModule>::Backup> =
            snapshot.map(|s| {
                s.as_any()
                    .downcast_ref()
                    .expect("can't convert client module backup to desired type")
            });

        Ok(self
            .recover(
                &ClientModuleRecoverArgs {
                    federation_id,
                    cfg: typed_cfg.clone(),
                    db: db.with_prefix_module_id(instance_id),
                    api_version,
                    module_root_secret,
                    notifier: notifier.module_notifier(instance_id),
                    api: api.clone(),
                    module_api: api.with_module(instance_id),
                    context: ClientContext {
                        client: final_client,
                        module_instance_id: instance_id,
                        module_db: db.with_prefix_module_id(instance_id),
                        _marker: marker::PhantomData,
                    },
                    progress_tx,
                },
                snapshot,
            )
            .await?)
    }

    async fn init(
        &self,
        final_client: FinalClient,
        federation_id: FederationId,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        // TODO: make dyn type for notifier
        notifier: Notifier<DynGlobalClientContext>,
        api: DynGlobalApi,
    ) -> anyhow::Result<DynClientModule> {
        let typed_cfg: &<<T as fedimint_core::module::ModuleInit>::Common as CommonModuleInit>::ClientConfig = cfg.cast()?;
        Ok(self
            .init(&ClientModuleInitArgs {
                federation_id,
                cfg: typed_cfg.clone(),
                db: db.with_prefix_module_id(instance_id),
                api_version,
                module_root_secret,
                notifier: notifier.module_notifier(instance_id),
                api: api.clone(),
                module_api: api.with_module(instance_id),
                context: ClientContext {
                    client: final_client,
                    module_instance_id: instance_id,
                    module_db: db.with_prefix_module_id(instance_id),
                    _marker: marker::PhantomData,
                },
            })
            .await?
            .into())
    }
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynClientModuleInit(Arc<IClientModuleInit>)
);

impl AsRef<dyn IDynCommonModuleInit + Send + Sync + 'static> for DynClientModuleInit {
    fn as_ref(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static) {
        self.inner.as_common()
    }
}

impl AsRef<dyn IClientModuleInit + 'static> for DynClientModuleInit {
    fn as_ref(&self) -> &(dyn IClientModuleInit + 'static) {
        self.inner.as_ref()
    }
}
