#![cfg_attr(target_family = "wasm", allow(dead_code))]

mod inner;

/// Just-in-time initialization
pub mod jit;
pub mod waiter;

use std::future::Future;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::bail;
use fedimint_core::time::now;
use fedimint_logging::{LOG_TASK, LOG_TEST};
use futures::future::{self, Either};
use inner::TaskGroupInner;
use thiserror::Error;
use tokio::sync::{oneshot, watch};
use tracing::{debug, error, info};

use crate::runtime;
// TODO: stop using `task::*`, and use `runtime::*` in the code
// lots of churn though
pub use crate::runtime::*;
/// A group of task working together
///
/// Using this struct it is possible to spawn one or more
/// main thread collaborating, which can cooperatively gracefully
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

    pub fn make_handle(&self) -> TaskHandle {
        TaskHandle {
            inner: self.inner.clone(),
        }
    }

    /// Create a sub-group
    ///
    /// Task subgroup works like an independent [`TaskGroup`], but the parent
    /// `TaskGroup` will propagate the shut down signal to a sub-group.
    ///
    /// In contrast to using the parent group directly, a subgroup allows
    /// calling [`Self::join_all`] and detecting any panics on just a
    /// subset of tasks.
    ///
    /// The code create a subgroup is responsible for calling
    /// [`Self::join_all`]. If it won't, the parent subgroup **will not**
    /// detect any panics in the tasks spawned by the subgroup.
    pub fn make_subgroup(&self) -> Self {
        let new_tg = Self::new();
        self.inner.add_subgroup(new_tg.clone());
        new_tg
    }

    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    pub async fn shutdown_join_all(
        self,
        join_timeout: impl Into<Option<Duration>>,
    ) -> Result<(), anyhow::Error> {
        self.shutdown();
        self.join_all(join_timeout.into()).await
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn install_kill_handler(&self) {
        use tokio::signal;

        async fn wait_for_shutdown_signal() {
            let ctrl_c = async {
                signal::ctrl_c()
                    .await
                    .expect("failed to install Ctrl+C handler");
            };

            #[cfg(unix)]
            let terminate = async {
                signal::unix::signal(signal::unix::SignalKind::terminate())
                    .expect("failed to install signal handler")
                    .recv()
                    .await;
            };

            #[cfg(not(unix))]
            let terminate = std::future::pending::<()>();

            tokio::select! {
                () = ctrl_c => {},
                () = terminate => {},
            }
        }
        runtime::spawn("kill handlers", {
            let task_group = self.clone();
            async move {
                wait_for_shutdown_signal().await;
                info!(
                    target: LOG_TASK,
                    "signal received, starting graceful shutdown"
                );
                task_group.shutdown();
            }
        });
    }

    pub fn spawn<Fut, R>(
        &self,
        name: impl Into<String>,
        f: impl FnOnce(TaskHandle) -> Fut + MaybeSend + 'static,
    ) -> oneshot::Receiver<R>
    where
        Fut: Future<Output = R> + MaybeSend + 'static,
        R: MaybeSend + 'static,
    {
        let name = name.into();
        let mut guard = TaskPanicGuard {
            name: name.clone(),
            inner: self.inner.clone(),
            completed: false,
        };
        let handle = self.make_handle();

        let (tx, rx) = oneshot::channel();
        let handle = crate::runtime::spawn(&name, {
            let name = name.clone();
            async move {
                // if receiver is not interested, just drop the message
                debug!("Starting task {name}");
                let r = f(handle).await;
                debug!("Finished task {name}");
                let _ = tx.send(r);
            }
        });
        self.inner.add_join_handle(name, handle);
        guard.completed = true;

        rx
    }

    pub fn spawn_local<Fut>(
        &self,
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

        let handle = runtime::spawn_local(name.as_str(), async {
            f(handle).await;
        });
        self.inner.add_join_handle(name, handle);
        guard.completed = true;
    }

    /// Spawn a task that will get cancelled automatically on `TaskGroup`
    /// shutdown.
    pub fn spawn_cancellable<R>(
        &self,
        name: impl Into<String>,
        future: impl Future<Output = R> + MaybeSend + 'static,
    ) -> oneshot::Receiver<Result<R, ShuttingDownError>>
    where
        R: MaybeSend + 'static,
    {
        self.spawn(name, |handle| async move {
            let value = handle.cancel_on_shutdown(future).await;
            if value.is_err() {
                // name will part of span
                debug!("task cancelled on shutdown");
            }
            value
        })
    }

    pub async fn join_all(self, timeout: Option<Duration>) -> Result<(), anyhow::Error> {
        let deadline = timeout.map(|timeout| now() + timeout);
        let mut errors = vec![];

        self.join_all_inner(deadline, &mut errors).await;

        if errors.is_empty() {
            Ok(())
        } else {
            let num_errors = errors.len();
            bail!("{num_errors} tasks did not finish cleanly: {errors:?}")
        }
    }

    #[cfg_attr(not(target_family = "wasm"), ::async_recursion::async_recursion)]
    #[cfg_attr(target_family = "wasm", ::async_recursion::async_recursion(?Send))]
    pub async fn join_all_inner(self, deadline: Option<SystemTime>, errors: &mut Vec<JoinError>) {
        self.inner.join_all(deadline, errors).await;
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
        self.inner.is_shutting_down()
    }
}

impl Drop for TaskPanicGuard {
    fn drop(&mut self) {
        if !self.completed {
            info!(
                target: LOG_TASK,
                "Task {} shut down uncleanly. Shutting down task group.", self.name
            );
            self.inner.shutdown();
        }
    }
}

#[derive(Clone, Debug)]
pub struct TaskHandle {
    inner: Arc<TaskGroupInner>,
}

#[derive(thiserror::Error, Debug, Clone)]
#[error("Task group is shutting down")]
#[non_exhaustive]
pub struct ShuttingDownError {}

impl TaskHandle {
    /// Is task group shutting down?
    ///
    /// Every task in a task group should detect and stop if `true`.
    pub fn is_shutting_down(&self) -> bool {
        self.inner.is_shutting_down()
    }

    /// Make a [`oneshot::Receiver`] that will fire on shutdown
    ///
    /// Tasks can use `select` on the return value to handle shutdown
    /// signal during otherwise blocking operation.
    pub fn make_shutdown_rx(&self) -> TaskShutdownToken {
        self.inner.make_shutdown_rx()
    }

    /// Run the future or cancel it if the [`TaskGroup`] shuts down.
    pub async fn cancel_on_shutdown<F: Future>(
        &self,
        fut: F,
    ) -> Result<F::Output, ShuttingDownError> {
        let rx = self.make_shutdown_rx();
        match future::select(pin!(rx), pin!(fut)).await {
            Either::Left(((), _)) => Err(ShuttingDownError {}),
            Either::Right((value, _)) => Ok(value),
        }
    }
}

pub struct TaskShutdownToken(Pin<Box<dyn Future<Output = ()> + Send>>);

impl TaskShutdownToken {
    fn new(mut rx: watch::Receiver<bool>) -> Self {
        Self(Box::pin(async move {
            let _ = rx.wait_for(|v| *v).await;
        }))
    }
}

impl Future for TaskShutdownToken {
    type Output = ();

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

/// async trait that use MaybeSend
///
/// # Example
///
/// ```rust
/// use fedimint_core::{apply, async_trait_maybe_send};
/// #[apply(async_trait_maybe_send!)]
/// trait Foo {
///     // methods
/// }
///
/// #[apply(async_trait_maybe_send!)]
/// impl Foo for () {
///     // methods
/// }
/// ```
#[macro_export]
macro_rules! async_trait_maybe_send {
    ($($tt:tt)*) => {
        #[cfg_attr(not(target_family = "wasm"), ::async_trait::async_trait)]
        #[cfg_attr(target_family = "wasm", ::async_trait::async_trait(?Send))]
        $($tt)*
    };
}

/// MaybeSync can not be used in `dyn $Trait + MaybeSend`
///
/// # Example
///
/// ```rust
/// use std::any::Any;
///
/// use fedimint_core::{apply, maybe_add_send};
/// type Foo = maybe_add_send!(dyn Any);
/// ```
#[cfg(not(target_family = "wasm"))]
#[macro_export]
macro_rules! maybe_add_send {
    ($($tt:tt)*) => {
        $($tt)* + Send
    };
}

/// MaybeSync can not be used in `dyn $Trait + MaybeSend`
///
/// # Example
///
/// ```rust
/// type Foo = maybe_add_send!(dyn Any);
/// ```
#[cfg(target_family = "wasm")]
#[macro_export]
macro_rules! maybe_add_send {
    ($($tt:tt)*) => {
        $($tt)*
    };
}

/// See `maybe_add_send`
#[cfg(not(target_family = "wasm"))]
#[macro_export]
macro_rules! maybe_add_send_sync {
    ($($tt:tt)*) => {
        $($tt)* + Send + Sync
    };
}

/// See `maybe_add_send`
#[cfg(target_family = "wasm")]
#[macro_export]
macro_rules! maybe_add_send_sync {
    ($($tt:tt)*) => {
        $($tt)*
    };
}

/// `MaybeSend` is no-op on wasm and `Send` on non wasm.
///
/// On wasm, most types don't implement `Send` because JS types can not sent
/// between workers directly.
#[cfg(target_family = "wasm")]
pub trait MaybeSend {}

/// `MaybeSend` is no-op on wasm and `Send` on non wasm.
///
/// On wasm, most types don't implement `Send` because JS types can not sent
/// between workers directly.
#[cfg(not(target_family = "wasm"))]
pub trait MaybeSend: Send {}

#[cfg(not(target_family = "wasm"))]
impl<T: Send> MaybeSend for T {}

#[cfg(target_family = "wasm")]
impl<T> MaybeSend for T {}

/// `MaybeSync` is no-op on wasm and `Sync` on non wasm.
#[cfg(target_family = "wasm")]
pub trait MaybeSync {}

/// `MaybeSync` is no-op on wasm and `Sync` on non wasm.
#[cfg(not(target_family = "wasm"))]
pub trait MaybeSync: Sync {}

#[cfg(not(target_family = "wasm"))]
impl<T: Sync> MaybeSync for T {}

#[cfg(target_family = "wasm")]
impl<T> MaybeSync for T {}

// Used in tests when sleep functionality is desired so it can be logged.
// Must include comment describing the reason for sleeping.
pub async fn sleep_in_test(comment: impl AsRef<str>, duration: Duration) {
    info!(
        target: LOG_TEST,
        "Sleeping for {}.{:03} seconds because: {}",
        duration.as_secs(),
        duration.subsec_millis(),
        comment.as_ref()
    );
    sleep(duration).await;
}

/// An error used as a "cancelled" marker in [`Cancellable`].
#[derive(Error, Debug)]
#[error("Operation cancelled")]
pub struct Cancelled;

/// Operation that can potentially get cancelled returning no result (e.g.
/// program shutdown).
pub type Cancellable<T> = std::result::Result<T, Cancelled>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test(tokio::test)]
    async fn shutdown_task_group_after() -> anyhow::Result<()> {
        let tg = TaskGroup::new();
        tg.spawn("shutdown waiter", |handle| async move {
            handle.make_shutdown_rx().await;
        });
        sleep(Duration::from_millis(10)).await;
        tg.shutdown_join_all(None).await?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn shutdown_task_group_before() -> anyhow::Result<()> {
        let tg = TaskGroup::new();
        tg.spawn("shutdown waiter", |handle| async move {
            sleep(Duration::from_millis(10)).await;
            handle.make_shutdown_rx().await;
        });
        tg.shutdown_join_all(None).await?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn shutdown_task_subgroup_after() -> anyhow::Result<()> {
        let tg = TaskGroup::new();
        tg.make_subgroup()
            .spawn("shutdown waiter", |handle| async move {
                handle.make_shutdown_rx().await;
            });
        sleep(Duration::from_millis(10)).await;
        tg.shutdown_join_all(None).await?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn shutdown_task_subgroup_before() -> anyhow::Result<()> {
        let tg = TaskGroup::new();
        tg.make_subgroup()
            .spawn("shutdown waiter", |handle| async move {
                sleep(Duration::from_millis(10)).await;
                handle.make_shutdown_rx().await;
            });
        tg.shutdown_join_all(None).await?;
        Ok(())
    }
}
