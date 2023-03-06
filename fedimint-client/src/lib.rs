//! Client library for fedimintd

use fedimint_core::core::Decoder;
use fedimint_core::module::ModuleCommon;

use crate::sm::State;

/// Client state machine interfaces and executor implementation
pub mod sm;

/// Fedimint module client
pub trait ClientModule {
    /// Common module types shared between client and server
    type Common: ModuleCommon;

    /// Data and API clients available to state machine transitions of this
    /// module
    type ModuleStateMachineContext;

    /// Data and API clients available to state machine transitions of all
    /// modules
    type GlobalStateMachineContext;

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
