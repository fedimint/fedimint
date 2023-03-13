mod executor;
/// State machine state interface
mod state;

use std::fmt::Debug;

pub use executor::{Executor, ExecutorBuilder};
use fedimint_core::task::{MaybeSend, MaybeSync};
pub use state::{Context, DynContext, DynState, OperationState, State, StateTransition};

/// Context given to all state machines
pub trait GlobalContext: Debug + MaybeSync + MaybeSend + 'static {}

impl GlobalContext for () {}

/// Unique identifier for one semantic, correlatable operation.
///
/// The concept of *operations* is used to avoid losing privacy while being as
/// efficient as possible with regards to network requests.
///
/// For Fedimint transactions to be private users need to communicate with the
/// federation using an anonymous communication network. If each API request was
/// done in a way that it cannot be correlated to any other API request we would
/// achieve privacy, but would reduce efficiency. E.g. on Tor we would need to
/// open a new circuit for every request and open a new web socket connection.
///
/// Fortunately we do not need to do that to maintain privacy. Many API requests
/// and transactions can be correlated by the federation anyway, in these cases
/// it does not make any difference to re-use the same network connection. All
/// requests, transactions, state machines that are connected from the
/// federation's point of view anyway are grouped together as one *operation*.
///
/// # Choice of Operation ID
///
/// In cases where an operation is created by a new transaction that's being
/// submitted the transaction's ID can be used as operation ID. If there is no
/// transaction related to it, it should be generated randomly. Since it is a
/// 256bit value collisions are impossible for all intents and purposes.
pub type OperationId = [u8; 32];
