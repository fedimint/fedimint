use std::sync::Arc;

use fedimint_logging::LOG_TASK;
use futures::Future;
use tokio::select;
use tokio::sync::{self, oneshot};
use tracing::trace;

use super::MaybeSend;

/// A value that initializes eagerly in parallel
#[derive(Debug, Clone)]
pub struct Jit<T> {
    // on last drop it lets the inner task to know it should stop, because we don't care anymore
    _cancel_tx: sync::mpsc::Sender<()>,
    // since joinhandles, are not portable, we use this to wait for the value
    // Note: the `std::sync::Mutex` is used intentionally, since contention never actually happens
    // and we want to avoid cancelation because of it
    val_rx: Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<T>>>>,
    val: sync::OnceCell<T>,
}

impl<T> Jit<T>
where
    T: MaybeSend,
{
    /// Create `Jit` value, and spawn a future `f` that computes its value
    ///
    /// Unlike normal Rust futures, the `f` executes eagerly (is spawned as a
    /// tokio task).
    pub fn new<Fut>(f: impl FnOnce() -> Fut + 'static + MaybeSend) -> Self
    where
        Fut: Future<Output = T> + 'static + MaybeSend,
        T: 'static,
    {
        let (cancel_tx, mut cancel_rx) = tokio::sync::mpsc::channel(1);
        let (val_tx, val_rx) = oneshot::channel();
        super::imp::spawn(
            &format!("Jit {} value", std::any::type_name::<T>()),
            async move {
                select! {
                    _ = cancel_rx.recv() => {
                        trace!(target: LOG_TASK, r#type = %std::any::type_name::<T>(), "Jit value future canceled");
                    },
                    val = f() => {
                        match val_tx.send(val) {
                            Ok(_) => {
                                trace!(target: LOG_TASK, r#type = %std::any::type_name::<T>(), "Jit value ready");
                            },
                            Err(_) => {
                                trace!(target: LOG_TASK,  r#type = %std::any::type_name::<T>(), "Jit value ready, but ignored");
                            },
                        };
                    },
                }
            },
        )
        .expect("spawn not fail");

        Self {
            _cancel_tx: cancel_tx,
            val_rx: Arc::new(Some(val_rx).into()),
            val: sync::OnceCell::new(),
        }
    }

    /// Get the reference to the value, potentially blocking for the
    /// initialization future to complete
    pub async fn get(&self) -> &T {
        #[allow(clippy::await_holding_lock)]
        self.val
            .get_or_init(|| async {
                self.val_rx
                    // this lock gets locked only once so it's kind of useless other than making
                    // Rust happy, but the overhead doesn't matter
                    .lock()
                    .expect("locking can't fail")
                    .as_mut()
                    .expect("value take only once")
                    .await
                    .unwrap_or_else(|_| panic!("Jit value {} panicked", std::any::type_name::<T>()))
            })
            .await
    }
}

/// A value that initializes eagerly in parallel in a falliable way
#[derive(Debug, Clone)]
pub struct JitTry<T> {
    // on last drop it lets the inner task to know it should stop, because we don't care anymore
    _cancel_tx: sync::mpsc::Sender<()>,
    // since joinhandles, are not portable, we use this to wait for the value
    // Note: the `std::sync::Mutex` is used intentionally, since contention never actually happens
    // and we want to avoid cancelation because of it
    val_rx: Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<anyhow::Result<T>>>>>,
    val: sync::OnceCell<T>,
}

impl<T> JitTry<T>
where
    T: MaybeSend,
{
    /// Create `JitTry` value, and spawn a future `f` that computes its value
    ///
    /// Unlike normal Rust futures, the `f` executes eagerly (is spawned as a
    /// tokio task).
    pub fn new<Fut>(f: impl FnOnce() -> Fut + 'static + MaybeSend) -> Self
    where
        Fut: Future<Output = anyhow::Result<T>> + 'static + MaybeSend,
        T: 'static,
    {
        let (cancel_tx, mut cancel_rx) = tokio::sync::mpsc::channel(1);
        let (val_tx, val_rx) = oneshot::channel();
        super::imp::spawn(
            &format!("JitTry {} value", std::any::type_name::<T>()),
            async move {
                select! {
                    _ = cancel_rx.recv() => {
                        trace!(target: LOG_TASK, r#type = %std::any::type_name::<T>(), "JitTry value future canceled");
                    },
                    val = f() => {
                        match val_tx.send(val) {
                            Ok(_) => {
                                trace!(target: LOG_TASK, r#type = %std::any::type_name::<T>(), "JitTry value ready");
                            },
                            Err(_) => {
                                trace!(target: LOG_TASK,  r#type = %std::any::type_name::<T>(), "JitTry value ready, but ignored");
                            },
                        };
                    },
                }
            },
        )
        .expect("spawn not fail");

        Self {
            _cancel_tx: cancel_tx,
            val_rx: Arc::new(Some(val_rx).into()),
            val: sync::OnceCell::new(),
        }
    }

    /// Get the reference to the value, potentially blocking for the
    /// initialization future to complete
    pub async fn get(&self) -> anyhow::Result<&T> {
        #[allow(clippy::await_holding_lock)]
        self.val
            .get_or_try_init(|| async {
                let val_res = self
                    .val_rx
                    // this lock gets locked only once so it's kind of useless other than making
                    // Rust happy, but the overhead doesn't matter
                    .lock()
                    .expect("locking can't fail")
                    .as_mut()
                    .ok_or_else(|| {
                        anyhow::format_err!("JitTry value failed, error already returned elsewhere")
                    })?
                    .await
                    .unwrap_or_else(|_| {
                        panic!("JitTry value {} panicked", std::any::type_name::<T>())
                    });
                self.val_rx.lock().expect("locking can't fail").take();
                val_res
            })
            .await
    }
}
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::bail;

    use super::{Jit, JitTry};

    #[test_log::test(tokio::test)]
    async fn sanity_jit() {
        let v = Jit::new(|| async {
            fedimint_core::task::sleep(Duration::from_millis(0)).await;
            3
        });

        assert_eq!(*v.get().await, 3);
    }

    #[test_log::test(tokio::test)]
    async fn sanity_jit_try_ok() {
        let v = JitTry::new(|| async {
            fedimint_core::task::sleep(Duration::from_millis(0)).await;
            Ok(3)
        });

        assert_eq!(*v.get().await.expect("ok"), 3);
    }

    #[test_log::test(tokio::test)]
    async fn sanity_jit_try_err() {
        let v = JitTry::new(|| async {
            fedimint_core::task::sleep(Duration::from_millis(0)).await;
            bail!("BOOM");
            #[allow(unreachable_code)]
            Ok(3)
        });

        assert!(v.get().await.is_err());
    }
}
