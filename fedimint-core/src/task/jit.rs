use std::convert::Infallible;
use std::fmt;
use std::sync::{Arc, Mutex as StdMutex};

use fedimint_logging::LOG_TASK;
use futures::Future;
use tokio::{select, sync};
use tracing::trace;

use super::waiter::Waiter;
use super::{MaybeSend, MaybeSync};

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
    shared: Arc<JitCoreShared<T, E>>,
}

#[derive(Debug)]
struct JitCoreShared<T, E> {
    val: std::sync::OnceLock<Result<T, StdMutex<Option<E>>>>,
    val_ready: Waiter,
}

impl<T, E> Clone for JitCore<T, E>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            _cancel_tx: self._cancel_tx.clone(),
            shared: self.shared.clone(),
        }
    }
}
impl<T, E> JitCore<T, E>
where
    T: MaybeSend + MaybeSync + 'static,
    E: MaybeSend + MaybeSync + 'static + fmt::Display,
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
        let type_name = std::any::type_name::<T>();
        let shared = Arc::new(JitCoreShared {
            val: std::sync::OnceLock::new(),
            val_ready: Waiter::new(),
        });
        let shared2 = shared.clone();
        super::imp::spawn(
            &format!("JitTry {} value", std::any::type_name::<T>()),
            async move {
                select! {
                    biased;
                    _ = cancel_rx.recv() => {
                        trace!(target: LOG_TASK, r#type = %type_name, "JitTry value future canceled");
                    },
                    val = f() => {
                        trace!(target: LOG_TASK, r#type = %type_name, "JitTry value ready");
                        if shared.val.set(val.map_err(|e| StdMutex::new(Some(e)))).is_err() {
                            unreachable!("set is only called once");
                        }
                        shared.val_ready.done();
                    },
                }
            },
        )
        .expect("spawn not fail");

        Self {
            _cancel_tx: cancel_tx,
            shared: shared2,
        }
    }

    /// Get the reference to the value, potentially blocking for the
    /// initialization future to complete
    pub async fn get_try(&self) -> Result<&T, OneTimeError<E>> {
        self.shared.val_ready.wait().await;
        match self
            .shared
            .val
            .get()
            .expect("must be initialized before waiter is done")
        {
            Ok(val) => Ok(val),
            Err(err_mutex) => Err(OneTimeError(err_mutex.lock().expect("lock poison").take())),
        }
    }
}
impl<T> JitCore<T, Infallible>
where
    T: MaybeSend + MaybeSync + 'static,
{
    pub fn new<Fut>(f: impl FnOnce() -> Fut + 'static + MaybeSend + MaybeSync) -> Self
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
