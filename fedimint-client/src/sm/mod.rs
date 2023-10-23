mod dbtx;
pub(crate) mod executor;
/// State machine state interface
mod state;
pub mod util;

// FIXME: use DB subscriptions? Needs prefix subscriptions :(
/// Helper to notify modules about state transitions
mod notifier;

use std::fmt::Debug;

pub use dbtx::ClientSMDatabaseTransaction;
pub use executor::{ActiveState, Executor, ExecutorBuilder, InactiveState};
use fedimint_core::task::{MaybeSend, MaybeSync};
pub use notifier::{ModuleNotifier, Notifier, NotifierSender};
pub use state::{Context, DynContext, DynState, IState, OperationState, State, StateTransition};

/// Context given to all state machines
pub trait GlobalContext: Debug + Clone + MaybeSync + MaybeSend + 'static {}

impl GlobalContext for () {}
