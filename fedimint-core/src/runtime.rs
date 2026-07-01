//! Abstraction over an executor so we can spawn tasks under WASM the same way
//! we do usually.

use std::future::Future;

use fedimint_logging::LOG_RUNTIME;
pub use n0_future::task::{JoinError, JoinHandle};
pub use n0_future::time::{Duration, Elapsed, Instant, sleep, sleep_until, timeout};
#[cfg(not(target_family = "wasm"))]
use tokio::runtime::RuntimeFlavor;
use tracing::{Instrument, Span};

use crate::task::MaybeSend;

pub fn spawn<F, T>(name: &str, future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + 'static + MaybeSend,
    T: MaybeSend + 'static,
{
    let span = tracing::debug_span!(target: LOG_RUNTIME, parent: None, "spawn", task = name);
    n0_future::task::spawn(future.instrument(span))
}

/// Like [`spawn`] but with an explicit parent span.
///
/// Events from the spawned future inherit fields from `parent` (e.g. `fed_id`
/// from the client span), including the lifecycle events emitted by
/// [`crate::task::TaskGroup`] around the user future.
pub fn spawn_with_span<F, T>(parent: &Span, name: &str, future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + 'static + MaybeSend,
    T: MaybeSend + 'static,
{
    let span = tracing::debug_span!(target: LOG_RUNTIME, parent: parent, "spawn", task = name);
    n0_future::task::spawn(future.instrument(span))
}

// Note: These functions only exist on non-wasm platforms and you need to handle
// them conditionally at the call site of packages that compile on wasm
#[cfg(not(target_family = "wasm"))]
pub fn block_in_place<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    // Some embedders (notably mobile UniFFI integrations) execute async calls
    // on a current-thread runtime where Tokio's block_in_place panics. In that
    // case, execute the closure directly instead of panicking.
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == RuntimeFlavor::CurrentThread)
    {
        return f();
    }

    // nosemgrep: ban-raw-block-in-place
    tokio::task::block_in_place(f)
}

#[cfg(not(target_family = "wasm"))]
pub fn block_on<F: Future>(future: F) -> F::Output {
    // nosemgrep: ban-raw-block-on
    tokio::runtime::Handle::current().block_on(future)
}
