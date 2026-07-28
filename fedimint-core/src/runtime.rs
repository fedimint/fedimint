//! Abstraction over an executor so we can spawn tasks under WASM the same way
//! we do usually.

use std::future::Future;

use fedimint_logging::LOG_RUNTIME;
pub use n0_future::task::{JoinError, JoinHandle};
pub use n0_future::time::{Duration, Elapsed, Instant, sleep, sleep_until, timeout};
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
    // nosemgrep: ban-raw-block-in-place
    tokio::task::block_in_place(f)
}

#[cfg(not(target_family = "wasm"))]
pub fn block_on<F: Future>(future: F) -> F::Output {
    // nosemgrep: ban-raw-block-on
    tokio::runtime::Handle::current().block_on(future)
}

/// The single, process-wide multi-threaded Tokio runtime that backs every
/// Fedimint UniFFI entry point.
///
/// UniFFI's `#[uniffi::export(async_runtime = "tokio")]` async methods are
/// polled by `async_compat::Compat` on whatever host thread (a Kotlin
/// coroutine dispatcher, a Swift `Task`, ...) drives the call. That thread
/// usually has no ambient Tokio runtime, so `async_compat` enters its own
/// global *current-thread* runtime. Any work *spawned* from that context
/// therefore runs on a current-thread runtime, and Fedimint's rocksdb access
/// uses [`block_in_place`], which aborts the process with "can call blocking
/// only when running on the multi-threaded runtime" when run inside such a
/// task.
///
/// Routing all spawned FFI work onto this dedicated multi-threaded runtime
/// keeps [`block_in_place`] valid regardless of which host thread drove the
/// poll. It is created once, lazily, and reused for the life of the process,
/// so this is a fixed worker pool — not a thread per call.
#[cfg(all(feature = "uniffi", not(target_family = "wasm")))]
pub fn ffi_runtime() -> &'static tokio::runtime::Runtime {
    use std::sync::OnceLock;
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("fedimint-ffi")
            .build()
            .expect("failed to build fedimint FFI runtime")
    })
}

/// Run `fut` to completion on the shared multi-threaded [`ffi_runtime`],
/// regardless of which (possibly current-thread) runtime is ambient on the
/// thread driving the FFI poll.
///
/// Wrap the body of a `#[uniffi::export(async_runtime = "tokio")]` async
/// method in this whenever its work — or anything it transitively spawns,
/// such as a client's state-machine executor — must run on genuine
/// multi-threaded workers.
#[cfg(all(feature = "uniffi", not(target_family = "wasm")))]
pub async fn ffi_spawn<F, T>(fut: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    ffi_runtime()
        .spawn(fut)
        .await
        .expect("fedimint FFI task panicked")
}

/// Spawn a detached background task that drives a UniFFI `subscribe_*`
/// callback loop on the shared multi-threaded [`ffi_runtime`].
///
/// This is only meant for the fire-and-forget background loops behind
/// `subscribe_*` FFI methods; the spawned task is detached. See
/// [`ffi_runtime`] for why a multi-threaded runtime is required here.
#[cfg(all(feature = "uniffi", not(target_family = "wasm")))]
pub fn ffi_spawn_subscription<F>(name: &str, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let span = tracing::debug_span!(target: LOG_RUNTIME, parent: None, "spawn", task = name);
    ffi_runtime().spawn(future.instrument(span));
}

/// wasm has no multi-threaded runtime and no [`block_in_place`] (rocksdb is
/// not used there), so the ambient-runtime hazard does not exist: just run
/// the future on the ambient executor like [`spawn`] does.
#[cfg(all(feature = "uniffi", target_family = "wasm"))]
pub async fn ffi_spawn<F: Future>(fut: F) -> F::Output {
    fut.await
}

#[cfg(all(feature = "uniffi", target_family = "wasm"))]
pub fn ffi_spawn_subscription<F>(name: &str, future: F)
where
    F: Future<Output = ()> + 'static,
{
    spawn(name, future);
}
