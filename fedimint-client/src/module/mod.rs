use std::fmt::Debug;
use std::sync::Arc;

use fedimint_core::core::{Decoder, ModuleInstanceId};
use fedimint_core::dyn_newtype_define;
use fedimint_core::module::ModuleCommon;
use fedimint_core::task::{MaybeSend, MaybeSync};

use crate::sm::{Context, DynContext, GlobalContext, State};

pub mod gen;

/// Fedimint module client
pub trait ClientModule: Debug + MaybeSend + MaybeSync + 'static {
    /// Common module types shared between client and server
    type Common: ModuleCommon;

    /// Data and API clients available to state machine transitions of this
    /// module
    type ModuleStateMachineContext: Context;

    /// Data and API clients available to state machine transitions of all
    /// modules
    type GlobalStateMachineContext: GlobalContext;

    /// All possible states this client can submit to the executor
    type States: State<
        Self::GlobalStateMachineContext,
        ModuleContext = Self::ModuleStateMachineContext,
    >;

    fn decoder() -> Decoder {
        let mut decoder_builder = Self::Common::decoder_builder();
        decoder_builder.with_decodable_type::<Self::States>();
        decoder_builder.build()
    }

    fn context(&self) -> Self::ModuleStateMachineContext;
}

pub trait IClientModule: Debug {
    fn decoder(&self) -> Decoder;

    fn context(&self, instance: ModuleInstanceId) -> DynContext;
}

impl<T> IClientModule for T
where
    T: ClientModule,
{
    fn decoder(&self) -> Decoder {
        T::decoder()
    }

    fn context(&self, instance: ModuleInstanceId) -> DynContext {
        DynContext::from_typed(instance, <T as ClientModule>::context(self))
    }
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynClientModule(Arc<IClientModule>)
);
