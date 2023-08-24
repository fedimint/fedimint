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

use crate::module::{ClientModule, DynClientModule};
use crate::sm::{ModuleNotifier, Notifier};
use crate::DynGlobalClientContext;

pub type ClientModuleInitRegistry = ModuleInitRegistry<DynClientModuleInit>;

#[apply(async_trait_maybe_send!)]
pub trait ClientModuleInit: ExtendsCommonModuleInit + Sized {
    type Module: ClientModule;

    /// Api versions of the corresponding server side module's API
    /// that this client module implementation can use.
    fn supported_api_versions(&self) -> MultiApiVersion;

    /// Initialize a [`ClientModule`] instance from its config
    #[allow(clippy::too_many_arguments)]
    async fn init(
        &self,
        federation_id: FederationId,
        cfg: <<Self as ExtendsCommonModuleInit>::Common as CommonModuleInit>::ClientConfig,
        db: Database,
        api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
        api: DynGlobalApi,
        module_api: DynModuleApi,
    ) -> anyhow::Result<Self::Module>;
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
            .init(
                federation_id,
                typed_cfg.clone(),
                db,
                api_version,
                module_root_secret,
                notifier.module_notifier(instance_id),
                api.clone(),
                api.with_module(instance_id),
            )
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
