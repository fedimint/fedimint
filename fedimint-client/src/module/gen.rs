use std::fmt::Debug;
use std::sync::Arc;

use fedimint_core::api::{DynGlobalApi, DynModuleApi};
use fedimint_core::config::{ClientModuleConfig, ModuleGenRegistry, TypedClientModuleConfig};
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::db::Database;
use fedimint_core::module::{
    ApiVersion, CommonModuleGen, ExtendsCommonModuleGen, IDynCommonModuleGen, MultiApiVersion,
};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, dyn_newtype_define};
use fedimint_derive_secret::DerivableSecret;

use crate::module::{ClientModule, DynClientModule};
use crate::sm::{ModuleNotifier, Notifier};
use crate::DynGlobalClientContext;

pub type ClientModuleGenRegistry = ModuleGenRegistry<DynClientModuleGen>;

#[apply(async_trait_maybe_send!)]
pub trait ClientModuleGen: ExtendsCommonModuleGen + Sized {
    type Module: ClientModule;
    type Config: TypedClientModuleConfig;

    /// Api versions of the corresponding server side module's API
    /// that this client module implementation can use.
    fn supported_api_versions(&self) -> MultiApiVersion;

    /// Initialize a [`ClientModule`] instance from its config
    #[allow(clippy::too_many_arguments)]
    async fn init(
        &self,
        cfg: Self::Config,
        db: Database,
        api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
        api: DynGlobalApi,
        module_api: DynModuleApi,
    ) -> anyhow::Result<Self::Module>;
}

#[apply(async_trait_maybe_send!)]
pub trait IClientModuleGen: IDynCommonModuleGen + Debug + MaybeSend + MaybeSync {
    fn decoder(&self) -> Decoder;

    fn module_kind(&self) -> ModuleKind;

    fn as_common(&self) -> &(dyn IDynCommonModuleGen + Send + Sync + 'static);

    /// See [`ClientModuleGen::supported_api_versions`]
    fn supported_api_versions(&self) -> MultiApiVersion;

    #[allow(clippy::too_many_arguments)]
    async fn init(
        &self,
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
impl<T> IClientModuleGen for T
where
    T: ClientModuleGen + 'static + MaybeSend + Sync,
{
    fn decoder(&self) -> Decoder {
        T::Module::decoder()
    }

    fn module_kind(&self) -> ModuleKind {
        <Self as ExtendsCommonModuleGen>::Common::KIND
    }

    fn as_common(&self) -> &(dyn IDynCommonModuleGen + Send + Sync + 'static) {
        self
    }

    fn supported_api_versions(&self) -> MultiApiVersion {
        <Self as ClientModuleGen>::supported_api_versions(self)
    }

    async fn init(
        &self,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        // TODO: make dyn type for notifier
        notifier: Notifier<DynGlobalClientContext>,
        api: DynGlobalApi,
    ) -> anyhow::Result<DynClientModule> {
        let typed_cfg = cfg.cast::<T::Config>()?;
        Ok(self
            .init(
                typed_cfg,
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
    pub DynClientModuleGen(Arc<IClientModuleGen>)
);

impl AsRef<dyn IDynCommonModuleGen + Send + Sync + 'static> for DynClientModuleGen {
    fn as_ref(&self) -> &(dyn IDynCommonModuleGen + Send + Sync + 'static) {
        self.0.as_common()
    }
}

impl AsRef<dyn IClientModuleGen + 'static> for DynClientModuleGen {
    fn as_ref(&self) -> &(dyn IClientModuleGen + 'static) {
        self.0.as_ref()
    }
}
