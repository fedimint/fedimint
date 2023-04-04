use std::fmt::Debug;
use std::sync::Arc;

use anyhow::bail;
use bitcoin_hashes::sha256;
use fedimint_core::config::{
    ClientModuleConfig, CommonModuleGenRegistry, ModuleGenRegistry, TypedClientModuleConfig,
};
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::db::Database;
use fedimint_core::module::{CommonModuleGen, ExtendsCommonModuleGen, IDynCommonModuleGen};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, dyn_newtype_define};

use crate::module::{ClientModule, DynClientModule, DynPrimaryClientModule};

pub type ClientModuleGenRegistry = ModuleGenRegistry<DynClientModuleGen>;

pub trait ClientModuleGenRegistryExt {
    fn to_common(&self) -> CommonModuleGenRegistry;
}

impl ClientModuleGenRegistryExt for ClientModuleGenRegistry {
    fn to_common(&self) -> CommonModuleGenRegistry {
        self.legacy_init_order_iter()
            .map(|(_k, v)| v.to_dyn_common())
            .collect()
    }
}

#[apply(async_trait_maybe_send!)]
pub trait ClientModuleGen: ExtendsCommonModuleGen + Sized {
    type Module: ClientModule;
    type Config: TypedClientModuleConfig;

    /// Initialize a [`ClientModule`] instance from its config
    async fn init(
        &self,
        cfg: Self::Config,
        db: Database,
        instance_id: ModuleInstanceId,
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
    /// ) -> anyhow::Result<DynPrimaryClientModule> {
    ///     Ok(self.init(cfg, db)?.into())
    /// }
    /// ```
    async fn init_primary(
        &self,
        _cfg: Self::Config,
        _db: Database,
    ) -> anyhow::Result<DynPrimaryClientModule> {
        bail!("Not a primary module")
    }
}

#[apply(async_trait_maybe_send!)]
pub trait IClientModuleGen: IDynCommonModuleGen + Debug + MaybeSend + MaybeSync {
    fn decoder(&self) -> Decoder;

    fn module_kind(&self) -> ModuleKind;

    fn hash_client_module(&self, config: serde_json::Value) -> anyhow::Result<sha256::Hash>;

    fn as_common(&self) -> &(dyn IDynCommonModuleGen + Send + Sync + 'static);

    async fn init(
        &self,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
    ) -> anyhow::Result<DynClientModule>;

    async fn init_primary(
        &self,
        cfg: ClientModuleConfig,
        db: Database,
    ) -> anyhow::Result<DynPrimaryClientModule>;
}

#[apply(async_trait_maybe_send!)]
impl<T> IClientModuleGen for T
where
    T: ClientModuleGen + 'static + MaybeSend + Sync,
{
    fn decoder(&self) -> Decoder {
        <Self as ExtendsCommonModuleGen>::Common::decoder()
    }

    fn module_kind(&self) -> ModuleKind {
        <Self as ExtendsCommonModuleGen>::Common::KIND
    }

    fn hash_client_module(&self, config: serde_json::Value) -> anyhow::Result<sha256::Hash> {
        <Self as ExtendsCommonModuleGen>::Common::hash_client_module(config)
    }

    fn as_common(&self) -> &(dyn IDynCommonModuleGen + Send + Sync + 'static) {
        self
    }

    async fn init(
        &self,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
    ) -> anyhow::Result<DynClientModule> {
        let typed_cfg = cfg.cast::<T::Config>()?;
        Ok(self.init(typed_cfg, db, instance_id).await?.into())
    }

    async fn init_primary(
        &self,
        cfg: ClientModuleConfig,
        db: Database,
    ) -> anyhow::Result<DynPrimaryClientModule> {
        let typed_cfg = cfg.cast::<T::Config>()?;
        Ok(self.init_primary(typed_cfg, db).await?)
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
