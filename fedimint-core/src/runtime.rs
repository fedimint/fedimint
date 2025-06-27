//! Abstraction over an executor so we can spawn tasks under WASM the same way
//! we do usually.

use std::future::Future;

use fedimint_logging::LOG_RUNTIME;
pub use n0_future::task::{JoinError, JoinHandle};
pub use n0_future::time::{Duration, Elapsed, Instant, sleep, sleep_until, timeout};
use tracing::Instrument;

use crate::task::MaybeSend;

pub fn spawn<F, T>(name: &str, future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + 'static + MaybeSend,
    T: MaybeSend + 'static,
{
    let span = tracing::debug_span!(target: LOG_RUNTIME, parent: None, "spawn", task = name);
    n0_future::task::spawn(future.instrument(span))
}

// Note: These functions only exist on non-wasm platforms and you need to handle
// them conditionally at the call site of packages that compile on wasm
#[cfg(not(target_family = "wasm"))]
pub fn block_in_place<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    // nosemgrep: ban-raw-block-in-place
    tokio::task::block_in_place(f)
}

#[cfg(not(target_family = "wasm"))]
pub fn block_on<F: Future>(future: F) -> F::Output {
    // nosemgrep: ban-raw-block-on
    tokio::runtime::Handle::current().block_on(future)
}
