//! Copyright 2021 The Matrix.org Foundation C.I.C.
//! Abstraction over an executor so we can spawn tasks under WASM the same way
//! we do usually.

// Adapted from https://github.com/matrix-org/matrix-rust-sdk

use std::future::Future;
use std::time::Duration;

use thiserror::Error;
use tokio::time::Instant;
use tracing::Instrument;

#[derive(Debug, Error)]
#[error("deadline has elapsed")]
pub struct Elapsed;

pub use self::r#impl::*;

#[cfg(not(target_family = "wasm"))]
mod r#impl {
    pub use tokio::task::{JoinError, JoinHandle};

    use super::*;

    pub fn spawn<F, T>(name: &str, future: F) -> tokio::task::JoinHandle<T>
    where
        F: Future<Output = T> + 'static + Send,
        T: Send + 'static,
    {
        let span = tracing::span!(tracing::Level::INFO, "spawn", task_name = name);
        // nosemgrep: ban-tokio-spawn
        tokio::spawn(future.instrument(span))
    }

    pub(crate) fn spawn_local<F>(name: &str, future: F) -> JoinHandle<()>
    where
        F: Future<Output = ()> + 'static,
    {
        let span = tracing::span!(tracing::Level::INFO, "spawn_local", task_name = name);
        // nosemgrep: ban-tokio-spawn
        tokio::task::spawn_local(future.instrument(span))
    }

    // note: this call does not exist on wasm and you need to handle it
    // conditionally at the call site of packages that compile on wasm
    pub fn block_in_place<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        // nosemgrep: ban-raw-block-in-place
        tokio::task::block_in_place(f)
    }

    // note: this call does not exist on wasm and you need to handle it
    // conditionally at the call site of packages that compile on wasm
    pub fn block_on<F: Future>(future: F) -> F::Output {
        // nosemgrep: ban-raw-block-on
        tokio::runtime::Handle::current().block_on(future)
    }

    pub async fn sleep(duration: Duration) {
        // nosemgrep: ban-tokio-sleep
        tokio::time::sleep(duration).await
    }

    pub async fn sleep_until(deadline: Instant) {
        tokio::time::sleep_until(deadline).await
    }

    pub async fn timeout<T>(duration: Duration, future: T) -> Result<T::Output, Elapsed>
    where
        T: Future,
    {
        tokio::time::timeout(duration, future)
            .await
            .map_err(|_| Elapsed)
    }
}

#[cfg(target_family = "wasm")]
mod r#impl {

    pub use std::convert::Infallible as JoinError;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use async_lock::{RwLock, RwLockReadGuard, RwLockWriteGuard};
    use futures_util::future::RemoteHandle;
    use futures_util::FutureExt;

    use super::*;

    #[derive(Debug)]
    pub struct JoinHandle<T> {
        handle: Option<RemoteHandle<T>>,
    }

    impl<T> JoinHandle<T> {
        pub fn abort(&mut self) {
            drop(self.handle.take());
        }
    }

    impl<T> Drop for JoinHandle<T> {
        fn drop(&mut self) {
            // don't abort the spawned future
            if let Some(h) = self.handle.take() {
                h.forget();
            }
        }
    }
    impl<T: 'static> Future for JoinHandle<T> {
        type Output = Result<T, JoinError>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if let Some(handle) = self.handle.as_mut() {
                Pin::new(handle).poll(cx).map(Ok)
            } else {
                Poll::Pending
            }
        }
    }

    pub fn spawn<F, T>(name: &str, future: F) -> JoinHandle<T>
    where
        F: Future<Output = T> + 'static,
    {
        let (fut, handle) = future.remote_handle();
        wasm_bindgen_futures::spawn_local(fut);

        JoinHandle {
            handle: Some(handle),
        }
    }

    pub(crate) fn spawn_local<F>(name: &str, future: F) -> JoinHandle<()>
    where
        // No Send needed on wasm
        F: Future<Output = ()> + 'static,
    {
        spawn(name, future)
    }

    pub async fn sleep(duration: Duration) {
        gloo_timers::future::sleep(duration.min(Duration::from_millis(i32::MAX as _))).await
    }

    pub async fn sleep_until(deadline: Instant) {
        // nosemgrep: ban-system-time-now
        // nosemgrep: ban-instant-now
        sleep(deadline.saturating_duration_since(Instant::now())).await
    }

    pub async fn timeout<T>(duration: Duration, future: T) -> Result<T::Output, Elapsed>
    where
        T: Future,
    {
        futures::pin_mut!(future);
        futures::select_biased! {
            value = future.fuse() => Ok(value),
            _ = sleep(duration).fuse() => Err(Elapsed),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn test_spawn_and_await() {
        let name = "test_spawn_and_await";
        let (tx, _rx) = oneshot::channel();

        let future = async move {
            // Simulating some work
            tokio::time::sleep(Duration::from_millis(1)).await;
            let _ = tx.send("done");
        };

        let _handle = spawn(name, future).await;
    }

    #[tokio::test]
    async fn test_sleep() {
        let duration = Duration::from_millis(1);
        let start = Instant::now();
        sleep(duration).await;
        let end = Instant::now();

        assert!(end - start >= duration);
    }

    #[tokio::test]
    async fn test_sleep_until() {
        let duration = Duration::from_millis(1);
        let deadline = Instant::now() + duration;
        sleep_until(deadline).await;
        let now = Instant::now();

        assert!(now >= deadline);
    }

    #[tokio::test]
    async fn test_timeout_elapsed() {
        let duration = Duration::from_millis(1);
        let future = async {
            tokio::time::sleep(duration * 2).await;
            "done"
        };

        let result = timeout(duration, future).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_timeout_completed() {
        let duration = Duration::from_millis(1);

        let (tx, rx) = oneshot::channel();

        let future = async move {
            tokio::time::sleep(duration / 2).await;
            let _ = tx.send("done");
        };

        tokio::select! {
            result = timeout(duration, future) => {
                assert!(result.is_ok());
            }
            _ = rx => {
                assert!(false, "Timeout occurred before future completed");
            }
        }
    }
}
