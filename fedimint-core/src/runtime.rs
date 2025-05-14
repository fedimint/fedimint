use std::future::Future;

use fedimint_logging::LOG_RUNTIME;
pub use n0_future::task::{JoinError, JoinHandle};
pub use n0_future::time::{Elapsed, Instant, SystemTime, sleep, sleep_until, timeout};
use tracing::Instrument;

pub fn spawn<F, T>(name: &str, future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + 'static + Send,
    T: Send + 'static,
{
    let span = tracing::debug_span!(target: LOG_RUNTIME, parent: None, "spawn", task = name);
    n0_future::task::spawn(future.instrument(span))
}

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
