use std::fmt::Debug;
use std::sync::Arc;

use fedimint_core::api::{DynGlobalApi, DynModuleApi};
use fedimint_core::config::{ClientModuleConfig, FederationId, ModuleInitRegistry};
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::db::Database;
use fedimint_core::module::{
    ApiVersion, CommonModuleInit, ExtendsCommonModuleInit, IDynCommonModuleInit, MultiApiVersion,
};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, dyn_newtype_define};
use fedimint_derive_secret::DerivableSecret;

use crate::module::recovery::RecoveringModule;
use crate::module::{ClientModule, DynClientModule};
use crate::sm::{ModuleNotifier, Notifier};
use crate::DynGlobalClientContext;

pub type ClientModuleInitRegistry = ModuleInitRegistry<DynClientModuleInit>;

pub struct ClientModuleInitArgs<C>
where
    C: ClientModuleInit,
{
    federation_id: FederationId,
    cfg: <<C as ExtendsCommonModuleInit>::Common as CommonModuleInit>::ClientConfig,
    db: Database,
    api_version: ApiVersion,
    module_root_secret: DerivableSecret,
    notifier: ModuleNotifier<
        DynGlobalClientContext,
        <<C as ClientModuleInit>::Module as ClientModule>::States,
    >,
    api: DynGlobalApi,
    module_api: DynModuleApi,
}

impl<C> ClientModuleInitArgs<C>
where
    C: ClientModuleInit,
{
    pub fn federation_id(&self) -> &FederationId {
        &self.federation_id
    }

    pub fn cfg(
        &self,
    ) -> &<<C as ExtendsCommonModuleInit>::Common as CommonModuleInit>::ClientConfig {
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
}

#[apply(async_trait_maybe_send!)]
pub trait ClientModuleInit: ExtendsCommonModuleInit + Sized {
    type Module: ClientModule;
    type RecoveringModule: RecoveringModule<ClientModule = Self::Module>;

    /// Api versions of the corresponding server side module's API
    /// that this client module implementation can use.
    fn supported_api_versions(&self) -> MultiApiVersion;

    /// Initialize a [`ClientModule`] instance from its config
    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module>;

    /// Initialize a [`RecoveringModule`] instance from the module config and
    /// secret. The method should only be called if no ongoing recovery has been
    /// persisted to disk.
    #[allow(clippy::too_many_arguments)]
    async fn init_recovering(
        &self,
        cfg: <<Self as ExtendsCommonModuleInit>::Common as CommonModuleInit>::ClientConfig,
        module_root_secret: DerivableSecret,
    ) -> anyhow::Result<Self::RecoveringModule>;
}

#[apply(async_trait_maybe_send!)]
pub trait IClientModuleInit: IDynCommonModuleInit + Debug + MaybeSend + MaybeSync {
    fn decoder(&self) -> Decoder;

    fn module_kind(&self) -> ModuleKind;

    fn as_common(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static);

    /// See [`ClientModuleInit::supported_api_versions`]
    fn supported_api_versions(&self) -> MultiApiVersion;

    #[allow(clippy::too_many_arguments)]
    async fn init(
        &self,
        federation_id: FederationId,
        cfg: ClientModuleConfig,
        db: Database,
        // FIXME: don't make modules aware of their instance id
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
        <Self as ExtendsCommonModuleInit>::Common::KIND
    }

    fn as_common(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static) {
        self
    }

    fn supported_api_versions(&self) -> MultiApiVersion {
        <Self as ClientModuleInit>::supported_api_versions(self)
    }

    async fn init(
        &self,
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
        let typed_cfg: &<<T as fedimint_core::module::ExtendsCommonModuleInit>::Common as CommonModuleInit>::ClientConfig = cfg.cast()?;
        Ok(self
            .init(&ClientModuleInitArgs {
                federation_id,
                cfg: typed_cfg.clone(),
                db,
                api_version,
                module_root_secret,
                notifier: notifier.module_notifier(instance_id),
                api: api.clone(),
                module_api: api.with_module(instance_id),
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
