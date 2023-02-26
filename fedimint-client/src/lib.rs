//! Client library for fedimintd

use fedimint_core::core::Decoder;

use crate::sm::State;

/// Client state machine interfaces and executor implementation
pub mod sm;

/// Fedimint module client
pub trait ClientModule {
    /// Data and API clients available to state machine transitions
    type StateMachineContext: Clone;
    /// All possible states this client can submit to the executor
    type States: State<ModuleContext = Self::StateMachineContext>;

    fn decoder(&self) -> Decoder;
    fn context(&self) -> Self::StateMachineContext;
}
