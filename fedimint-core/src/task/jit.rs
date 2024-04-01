use std::convert::Infallible;
use std::fmt;
use std::sync::Arc;

use fedimint_logging::LOG_TASK;
use futures::Future;
use tokio::select;
use tokio::sync::{self, oneshot};
use tracing::trace;

use super::MaybeSend;

pub type Jit<T> = JitCore<T, Infallible>;
pub type JitTry<T, E> = JitCore<T, E>;
pub type JitTryAnyhow<T> = JitCore<T, anyhow::Error>;

/// Error that could have been returned before
///
/// Newtype over `Option<E>` that allows better user (error conversion mostly)
/// experience
#[derive(Debug)]
pub struct OneTimeError<E>(Option<E>);

impl<E> std::error::Error for OneTimeError<E>
where
    E: fmt::Debug,
    E: fmt::Display,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}

impl<E> fmt::Display for OneTimeError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(e) = self.0.as_ref() {
            fmt::Display::fmt(&e, f)
        } else {
            f.write_str("Error: (missing, it was returned before)")
        }
    }
}

/// A value that initializes eagerly in parallel in a falliable way
#[derive(Debug)]
pub struct JitCore<T, E> {
    // on last drop it lets the inner task to know it should stop, because we don't care anymore
    _cancel_tx: sync::mpsc::Sender<()>,
    // since joinhandles, are not portable, we use this to wait for the value
    // Note: the `std::sync::Mutex` is used intentionally, since contention never actually happens
    // and we want to avoid cancelation because of it
    #[allow(clippy::type_complexity)]
    val_rx:
        Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<std::result::Result<T, E>>>>>,
    val: Arc<sync::OnceCell<T>>,
}

impl<T, E> Clone for JitCore<T, E>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            _cancel_tx: self._cancel_tx.clone(),
            val_rx: self.val_rx.clone(),
            val: self.val.clone(),
        }
    }
}
impl<T, E> JitCore<T, E>
where
    T: MaybeSend + 'static,
    E: MaybeSend + 'static + fmt::Display,
{
    /// Create `JitTry` value, and spawn a future `f` that computes its value
    ///
    /// Unlike normal Rust futures, the `f` executes eagerly (is spawned as a
    /// tokio task).
    pub fn new_try<Fut>(f: impl FnOnce() -> Fut + 'static + MaybeSend) -> Self
    where
        Fut: Future<Output = std::result::Result<T, E>> + 'static + MaybeSend,
    {
        let (cancel_tx, mut cancel_rx) = tokio::sync::mpsc::channel(1);
        let (val_tx, val_rx) = oneshot::channel();
        let type_name = std::any::type_name::<T>();
        super::imp::spawn(
            &format!("JitTry {} value", std::any::type_name::<T>()),
            async move {
                select! {
                    _ = cancel_rx.recv() => {
                        trace!(target: LOG_TASK, r#type = %type_name, "JitTry value future canceled");
                    },
                    val = f() => {
                        match val_tx.send(val) {
                            Ok(_) => {
                                trace!(target: LOG_TASK, r#type = %type_name, "JitTry value ready");
                            },
                            Err(_) => {
                                trace!(target: LOG_TASK,  r#type = %type_name, "JitTry value ready, but ignored");
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
            val: sync::OnceCell::new().into(),
        }
    }

    /// Get the reference to the value, potentially blocking for the
    /// initialization future to complete
    pub async fn get_try(&self) -> std::result::Result<&T, OneTimeError<E>> {
        /// Temporarily taken data out of `arc`, that will be put back on drop,
        /// unless canceled
        ///
        /// Used to achieve cancelation safety.
        struct PutBack<'a, T> {
            val: Option<T>,
            arc: &'a Arc<std::sync::Mutex<Option<T>>>,
        }

        impl<'a, T> PutBack<'a, T> {
            fn take(arc: &'a Arc<std::sync::Mutex<Option<T>>>) -> Self {
                let val = arc.lock().expect("lock failed").take();
                Self { val, arc }
            }

            fn cancel(mut self) {
                self.val = None;
            }

            fn get_mut(&mut self) -> Option<&mut T> {
                self.val.as_mut()
            }
        }
        impl<'a, T> Drop for PutBack<'a, T> {
            fn drop(&mut self) {
                let mut lock = self.arc.lock().expect("lock failed");
                let take = self.val.take();

                *lock = take;
            }
        }
        self.val
            .get_or_try_init(|| async {
                let mut recv = PutBack::take(&self.val_rx);

                let val_res = {
                    let Some(recv) = recv.get_mut() else {
                        return Err(OneTimeError(None));
                    };
                    recv.await.unwrap_or_else(|_| {
                        panic!("Jit value {} panicked", std::any::type_name::<T>())
                    })
                };

                recv.cancel();

                val_res.map_err(|err| OneTimeError(Some(err)))
            })
            .await
    }
}
impl<T> JitCore<T, Infallible>
where
    T: MaybeSend + 'static,
{
    pub fn new<Fut>(f: impl FnOnce() -> Fut + 'static + MaybeSend) -> Self
    where
        Fut: Future<Output = T> + 'static + MaybeSend,
        T: 'static,
    {
        Self::new_try(|| async { Ok(f().await) })
    }

    pub async fn get(&self) -> &T {
        self.get_try().await.expect("can't fail")
    }
}
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::bail;

    use super::{Jit, JitTry, JitTryAnyhow};

    #[test_log::test(tokio::test)]
    async fn sanity_jit() {
        let v = Jit::new(|| async {
            fedimint_core::task::sleep(Duration::from_millis(0)).await;
            3
        });

        assert_eq!(*v.get().await, 3);
        assert_eq!(*v.get().await, 3);
        assert_eq!(*v.clone().get().await, 3);
    }

    #[test_log::test(tokio::test)]
    async fn sanity_jit_try_ok() {
        let v = JitTryAnyhow::new_try(|| async {
            fedimint_core::task::sleep(Duration::from_millis(0)).await;
            Ok(3)
        });

        assert_eq!(*v.get_try().await.expect("ok"), 3);
        assert_eq!(*v.get_try().await.expect("ok"), 3);
        assert_eq!(*v.clone().get_try().await.expect("ok"), 3);
    }

    #[test_log::test(tokio::test)]
    async fn sanity_jit_try_err() {
        let v = JitTry::new_try(|| async {
            fedimint_core::task::sleep(Duration::from_millis(0)).await;
            bail!("BOOM");
            #[allow(unreachable_code)]
            Ok(3)
        });

        assert!(v.get_try().await.is_err());
        assert!(v.get_try().await.is_err());
        assert!(v.clone().get_try().await.is_err());
    }
}
