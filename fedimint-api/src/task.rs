use std::future::Future;
use std::time::{Duration, Instant};

use thiserror::Error;

#[derive(Debug, Error)]
#[error("deadline has elapsed")]
pub struct Elapsed;

#[cfg(not(target_family = "wasm"))]
mod imp {
    pub use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

    use super::*;

    pub fn spawn<F>(future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(future);
    }

    pub fn block_in_place<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        tokio::task::block_in_place(f)
    }

    pub async fn sleep(duration: Duration) {
        tokio::time::sleep(duration).await
    }

    pub async fn sleep_until(deadline: Instant) {
        tokio::time::sleep_until(deadline.into()).await
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
mod imp {
    pub use async_lock::{RwLock, RwLockReadGuard, RwLockWriteGuard};
    use futures::FutureExt;

    use super::*;

    pub fn spawn<F>(future: F)
    where
        // No Send needed on wasm
        F: Future<Output = ()> + 'static,
    {
        wasm_bindgen_futures::spawn_local(future)
    }

    pub fn block_in_place<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        // no such hint on wasm
        f()
    }

    pub async fn sleep(duration: Duration) {
        gloo_timers::future::sleep(duration).await
    }

    pub async fn sleep_until(deadline: Instant) {
        gloo_timers::future::sleep(deadline.saturating_duration_since(Instant::now())).await
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

pub use imp::*;
