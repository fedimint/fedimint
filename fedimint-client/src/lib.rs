//! Client library for fedimintd

use fedimint_core::core::Decoder;

use crate::sm::State;

/// Client state machine interfaces and executor implementation
pub mod sm;

/// Fedimint module client
pub trait ClientModule {
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

    fn decoder(&self) -> Decoder;
    fn context(&self) -> Self::ModuleStateMachineContext;
}
