use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use super::ModuleKind;
use crate::core::Decoder;
use crate::core::PluginDecode;
use crate::module::TransactionItemAmount;
use crate::{dyn_newtype_define, ServerModule};

#[async_trait]
pub trait ClientModule: Debug {
    const KIND: &'static str;
    type Decoder: PluginDecode;
    type Module: ServerModule;

    fn module_kind() -> ModuleKind {
        ModuleKind::from_static_str(Self::KIND)
    }

    fn decoder(&self) -> Self::Decoder;

    /// Returns the amount represented by the input and the fee its processing requires
    fn input_amount(&self, input: &<Self::Module as ServerModule>::Input) -> TransactionItemAmount;

    /// Returns the amount represented by the output and the fee its processing requires
    fn output_amount(
        &self,
        output: &<Self::Module as ServerModule>::Output,
    ) -> TransactionItemAmount;
}

pub trait IClientModule: Debug {
    fn as_any(&self) -> &dyn Any;

    /// Return the type-erased decoder of the module
    fn decoder(&self) -> Decoder;
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynClientModule(Arc<IClientModule>)
);

impl<T> IClientModule for T
where
    T: ClientModule + 'static,
{
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn decoder(&self) -> Decoder {
        Decoder::from_typed(<T as ClientModule>::decoder(self))
    }
}
