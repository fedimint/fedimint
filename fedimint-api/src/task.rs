use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use futures::lock::Mutex;
pub use imp::*;
use thiserror::Error;
#[cfg(not(target_family = "wasm"))]
use tokio::sync::oneshot;
#[cfg(not(target_family = "wasm"))]
use tokio::task::JoinHandle;
use tracing::debug;
use tracing::info;
#[cfg(target_family = "wasm")]
type JoinHandle<T> = futures::future::Ready<anyhow::Result<T>>;

#[derive(Debug, Error)]
#[error("deadline has elapsed")]
pub struct Elapsed;

#[derive(Debug, Default)]
struct TaskGroupInner {
    /// Was the shutdown requested, either externally or due to any task failure?
    is_shutting_down: AtomicBool,
    on_shutdown: Mutex<Vec<Box<dyn FnOnce() + Send>>>,
    join: Mutex<Vec<(String, JoinHandle<()>)>>,
}

impl TaskGroupInner {
    pub async fn shutdown(&self) {
        loop {
            let f_opt = self.on_shutdown.lock().await.pop();

            if let Some(f) = f_opt {
                f();
            } else {
                break;
            }
        }
        self.is_shutting_down.store(true, SeqCst);
    }
}
/// A group of task working together
///
/// Using this struct it is possible to spawn one or more
/// main thread collabarating, which can cooperatively gracefully
/// shut down, either due to external request, or failure of
/// one of them.
///
/// Each thread should periodically check [`TaskHandle`] or rely
/// on condition like channel disconnection to detect when it is time
/// to finish.
#[derive(Clone, Default, Debug)]
pub struct TaskGroup {
    inner: Arc<TaskGroupInner>,
}

impl TaskGroup {
    pub fn new() -> Self {
        Self::default()
    }

    fn make_handle(&self) -> TaskHandle {
        TaskHandle {
            inner: self.inner.clone(),
        }
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown().await
    }

    pub async fn shutdown_join_all(self) -> anyhow::Result<()> {
        self.shutdown().await;
        self.join_all().await
    }

    #[cfg(not(target_family = "wasm"))]
    pub async fn spawn<Fut>(
        &mut self,
        name: impl Into<String>,
        f: impl FnOnce(TaskHandle) -> Fut + Send + 'static,
    ) where
        Fut: Future<Output = ()> + Send + 'static,
    {
        let name = name.into();
        let mut guard = TaskPanicGuard {
            name: name.clone(),
            inner: self.inner.clone(),
            completed: false,
        };
        let handle = self.make_handle();

        if let Some(handle) = self::imp::spawn(async move {
            f(handle).await;
        }) {
            self.inner.join.lock().await.push((name, handle));
        }
        guard.completed = true;
    }

    #[cfg(not(target_family = "wasm"))]
    pub async fn spawn_local<Fut>(
        &mut self,
        name: impl Into<String>,
        f: impl FnOnce(TaskHandle) -> Fut + 'static,
    ) where
        Fut: Future<Output = ()> + 'static,
    {
        let name = name.into();
        let mut guard = TaskPanicGuard {
            name: name.clone(),
            inner: self.inner.clone(),
            completed: false,
        };
        let handle = self.make_handle();

        if let Some(handle) = self::imp::spawn_local(async move {
            f(handle).await;
        }) {
            self.inner.join.lock().await.push((name, handle));
        }
        guard.completed = true;
    }
    // TODO: Send vs lack of Send bound; do something about it
    #[cfg(target_family = "wasm")]
    pub async fn spawn<Fut>(
        &mut self,
        name: impl Into<String>,
        f: impl FnOnce(TaskHandle) -> Fut + 'static,
    ) where
        Fut: Future<Output = ()> + 'static,
    {
        let name = name.into();
        let mut guard = TaskPanicGuard {
            name: name.clone(),
            inner: self.inner.clone(),
            completed: false,
        };
        let handle = self.make_handle();

        if let Some(handle) = self::imp::spawn(async move {
            f(handle).await;
        }) {
            self.inner.join.lock().await.push((name, handle));
        }
        guard.completed = true;
    }

    pub async fn join_all(self) -> anyhow::Result<()> {
        for (name, join) in self.inner.join.lock().await.drain(..) {
            debug!("Waiting for {name} task to finish");
            join.await
                .map_err(|e| anyhow!("Thread {name} panicked with: {e}"))?;
            debug!("{name} task finished.");
        }
        Ok(())
    }
}

pub struct TaskPanicGuard {
    name: String,
    inner: Arc<TaskGroupInner>,
    /// Did the future completed successfully (no panic)
    completed: bool,
}

impl TaskPanicGuard {
    pub fn is_shutting_down(&self) -> bool {
        self.inner.is_shutting_down.load(SeqCst)
    }
}

impl Drop for TaskPanicGuard {
    fn drop(&mut self) {
        if !self.completed {
            info!(
                "Task {} shut down uncleanly. Shutting down task group.",
                self.name
            );
            self.inner.is_shutting_down.store(true, SeqCst);
        }
    }
}

pub struct TaskHandle {
    inner: Arc<TaskGroupInner>,
}

impl TaskHandle {
    /// Is task group shutting down?
    ///
    /// Every task in a task group should detect and stop if `true`.
    pub fn is_shutting_down(&self) -> bool {
        self.inner.is_shutting_down.load(SeqCst)
    }

    pub async fn on_shutdown(&self, f: impl FnOnce() + Send + 'static) {
        self.inner.on_shutdown.lock().await.push(Box::new(f))
    }

    /// Make a [`oneshot::Receiver`] that will fire on shutdown
    ///
    /// Tasks can use `select` on the return value to handle shutdown
    /// signal during otherwise blocking operation.
    #[cfg(not(target_family = "wasm"))]
    pub async fn make_shutdown_rx(&self) -> oneshot::Receiver<()> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.on_shutdown(|| {
            let _ = shutdown_tx.send(());
        })
        .await;

        shutdown_rx
    }
}

#[cfg(not(target_family = "wasm"))]
mod imp {
    pub use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

    use super::*;

    pub(crate) fn spawn<F>(future: F) -> Option<JoinHandle<()>>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Some(tokio::spawn(future))
    }

    pub(crate) fn spawn_local<F>(future: F) -> Option<JoinHandle<()>>
    where
        F: Future<Output = ()> + 'static,
    {
        Some(tokio::task::spawn_local(future))
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

    pub(crate) fn spawn<F>(future: F) -> Option<JoinHandle<()>>
    where
        // No Send needed on wasm
        F: Future<Output = ()> + 'static,
    {
        wasm_bindgen_futures::spawn_local(future);
        None
    }

    pub(crate) fn spawn_local<F>(future: F) -> Option<JoinHandle<()>>
    where
        // No Send needed on wasm
        F: Future<Output = ()> + 'static,
    {
        self::spawn(future)
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
