use std::fmt::Debug;
use std::sync::Arc;

use bitcoin_hashes::sha256;
use fedimint_core::config::{CommonModuleGenRegistry, ModuleGenRegistry};
use fedimint_core::core::{Decoder, ModuleKind};
use fedimint_core::module::{CommonModuleGen, ExtendsCommonModuleGen, IDynCommonModuleGen};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, dyn_newtype_define};

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
pub trait ClientModuleGen: ExtendsCommonModuleGen + Sized {}

pub trait IClientModuleGen: IDynCommonModuleGen + Debug + MaybeSend + MaybeSync {
    fn decoder(&self) -> Decoder;

    fn module_kind(&self) -> ModuleKind;

    fn hash_client_module(&self, config: serde_json::Value) -> anyhow::Result<sha256::Hash>;

    fn as_common(&self) -> &(dyn IDynCommonModuleGen + Send + Sync + 'static);
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
