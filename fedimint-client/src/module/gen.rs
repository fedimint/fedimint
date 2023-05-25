use std::fmt::Debug;
use std::sync::Arc;

use anyhow::bail;
use fedimint_core::config::{ClientModuleConfig, ModuleGenRegistry, TypedClientModuleConfig};
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::db::Database;
use fedimint_core::module::{CommonModuleGen, ExtendsCommonModuleGen, IDynCommonModuleGen};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, dyn_newtype_define};
use fedimint_derive_secret::DerivableSecret;

use crate::module::{ClientModule, DynClientModule, DynPrimaryClientModule};
use crate::sm::{ModuleNotifier, Notifier};
use crate::DynGlobalClientContext;

pub type ClientModuleGenRegistry = ModuleGenRegistry<DynClientModuleGen>;

#[apply(async_trait_maybe_send!)]
pub trait ClientModuleGen: ExtendsCommonModuleGen + Sized {
    type Module: ClientModule;
    type Config: TypedClientModuleConfig;

    /// Initialize a [`ClientModule`] instance from its config
    async fn init(
        &self,
        cfg: Self::Config,
        db: Database,
        module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    ) -> anyhow::Result<Self::Module>;

    /// Initialize a [`crate::module::PrimaryClientModule`] instance from its
    /// config
    ///
    /// The default implementation returns an error, assuming that the module is
    /// not a primary one. If it is the default impl has to be overridden as
    /// follows:
    ///
    /// ```compile_fail
    /// async fn init_primary(
    ///     &self,
    ///     cfg: Self::Config,
    ///     db: Database,
    ///     module_root_secret: DerivableSecret,
    ///     notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    /// ) -> anyhow::Result<DynPrimaryClientModule> {
    ///     Ok(self.init(cfg, db, instance_id, module_root_secret, notifier)?.into())
    /// }
    /// ```
    async fn init_primary(
        &self,
        _cfg: Self::Config,
        _db: Database,
        _module_root_secret: DerivableSecret,
        _notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    ) -> anyhow::Result<DynPrimaryClientModule> {
        bail!("Not a primary module")
    }
}

#[apply(async_trait_maybe_send!)]
pub trait IClientModuleGen: IDynCommonModuleGen + Debug + MaybeSend + MaybeSync {
    fn decoder(&self) -> Decoder;

    fn module_kind(&self) -> ModuleKind;

    fn as_common(&self) -> &(dyn IDynCommonModuleGen + Send + Sync + 'static);

    async fn init(
        &self,
        cfg: ClientModuleConfig,
        db: Database,
        // FIXME: don't make modules aware of their instance id
        instance_id: ModuleInstanceId,
        module_root_secret: DerivableSecret,
        notifier: Notifier<DynGlobalClientContext>,
    ) -> anyhow::Result<DynClientModule>;

    async fn init_primary(
        &self,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        module_root_secret: DerivableSecret,
        // TODO: make dyn type for notifier
        notifier: Notifier<DynGlobalClientContext>,
    ) -> anyhow::Result<DynPrimaryClientModule>;
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

    async fn init(
        &self,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        module_root_secret: DerivableSecret,
        // TODO: make dyn type for notifier
        notifier: Notifier<DynGlobalClientContext>,
    ) -> anyhow::Result<DynClientModule> {
        let typed_cfg = cfg.cast::<T::Config>()?;
        Ok(self
            .init(
                typed_cfg,
                db,
                module_root_secret,
                notifier.module_notifier(instance_id),
            )
            .await?
            .into())
    }

    async fn init_primary(
        &self,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        module_root_secret: DerivableSecret,
        notifier: Notifier<DynGlobalClientContext>,
    ) -> anyhow::Result<DynPrimaryClientModule> {
        let typed_cfg = cfg.cast::<T::Config>()?;
        Ok(self
            .init_primary(
                typed_cfg,
                db,
                module_root_secret,
                notifier.module_notifier(instance_id),
            )
            .await?)
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
