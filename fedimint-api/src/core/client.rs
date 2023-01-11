use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use super::ModuleKind;
use crate::core::Decoder;
use crate::core::PluginDecode;
use crate::module::TransactionItemAmount;
use crate::{dyn_newtype_define, ServerModulePlugin};

#[async_trait]
pub trait ClientModulePlugin: Debug {
    const KIND: &'static str;
    type Decoder: PluginDecode;
    type Module: ServerModulePlugin;

    fn module_kind() -> ModuleKind {
        ModuleKind::from_static_str(Self::KIND)
    }

    fn decoder(&self) -> Self::Decoder;

    /// Returns the amount represented by the input and the fee its processing requires
    fn input_amount(
        &self,
        input: &<Self::Module as ServerModulePlugin>::Input,
    ) -> TransactionItemAmount;

    /// Returns the amount represented by the output and the fee its processing requires
    fn output_amount(
        &self,
        output: &<Self::Module as ServerModulePlugin>::Output,
    ) -> TransactionItemAmount;
}

pub trait IClientModule: Debug {
    fn as_any(&self) -> &dyn Any;

    /// Return the type-erased decoder of the module
    fn decoder(&self) -> Decoder;
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub ClientModule(Arc<IClientModule>)
);

impl<T> IClientModule for T
where
    T: ClientModulePlugin + 'static,
    <T as ClientModulePlugin>::Decoder: Sync + Send + 'static,
{
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn decoder(&self) -> Decoder {
        Decoder::from_typed(<T as ClientModulePlugin>::decoder(self))
    }
}
