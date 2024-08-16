use std::convert::Infallible;
use std::sync::Arc;
use std::{fmt, panic};

use fedimint_core::runtime::JoinHandle;
use fedimint_logging::LOG_TASK;
use futures::Future;
use tokio::sync;
use tracing::warn;

use super::MaybeSend;

pub type Jit<T> = JitCore<T, Infallible>;
pub type JitTry<T, E> = JitCore<T, E>;
pub type JitTryAnyhow<T> = JitCore<T, anyhow::Error>;

/// Error that could have been returned before
///
/// Newtype over `Option<E>` that allows better user (error conversion mostly)
/// experience
#[derive(Debug)]
pub enum OneTimeError<E> {
    Original(E),
    Copy(anyhow::Error),
}

impl<E> std::error::Error for OneTimeError<E>
where
    E: fmt::Debug + fmt::Display,
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
        match self {
            Self::Original(o) => o.fmt(f),
            Self::Copy(c) => c.fmt(f),
        }
    }
}

/// A value that initializes eagerly in parallel in a falliable way
#[derive(Debug)]
pub struct JitCore<T, E> {
    inner: Arc<JitInner<T, E>>,
}

#[derive(Debug)]
struct JitInner<T, E> {
    handle: sync::Mutex<JoinHandle<Result<T, E>>>,
    val: sync::OnceCell<Result<T, String>>,
}

impl<T, E> Clone for JitCore<T, E>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
impl<T, E> Drop for JitInner<T, E> {
    fn drop(&mut self) {
        self.handle.get_mut().abort();
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
        let handle = crate::runtime::spawn("jit-value", async { f().await });

        Self {
            inner: JitInner {
                handle: handle.into(),
                val: sync::OnceCell::new(),
            }
            .into(),
        }
    }

    /// Get the reference to the value, potentially blocking for the
    /// initialization future to complete
    pub async fn get_try(&self) -> Result<&T, OneTimeError<E>> {
        let mut init_error = None;
        let value = self
            .inner
            .val
            .get_or_init(|| async {
                let handle: &mut _ = &mut *self.inner.handle.lock().await;
                match handle.await {
                        Ok(Ok(o)) => Ok(o),
                        Ok(Err(err)) => {
                            let err_str = err.to_string();
                            init_error = Some(err);
                            Err(err_str)
                        },
                        Err(err) => {

                            #[cfg(not(target_family = "wasm"))]
                            if err.is_panic() {
                                warn!(target: LOG_TASK, %err, type_name = %std::any::type_name::<T>(), "Jit value panicked");
                                // Resume the panic on the main task
                                panic::resume_unwind(err.into_panic());
                            }
                            #[cfg(not(target_family = "wasm"))]
                            if err.is_cancelled() {
                                warn!(target: LOG_TASK, %err, type_name = %std::any::type_name::<T>(), "Jit value task canceled:");
                            }
                            Err(format!("Jit value {} failed unexpectedly with: {}", std::any::type_name::<T>(), err))
                        },
                    }
            })
            .await;
        if let Some(err) = init_error {
            return Err(OneTimeError::Original(err));
        }
        value
            .as_ref()
            .map_err(|err_str| OneTimeError::Copy(anyhow::Error::msg(err_str.to_owned())))
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
            fedimint_core::runtime::sleep(Duration::from_millis(0)).await;
            3
        });

        assert_eq!(*v.get().await, 3);
        assert_eq!(*v.get().await, 3);
        assert_eq!(*v.clone().get().await, 3);
    }

    #[test_log::test(tokio::test)]
    async fn sanity_jit_try_ok() {
        let v = JitTryAnyhow::new_try(|| async {
            fedimint_core::runtime::sleep(Duration::from_millis(0)).await;
            Ok(3)
        });

        assert_eq!(*v.get_try().await.expect("ok"), 3);
        assert_eq!(*v.get_try().await.expect("ok"), 3);
        assert_eq!(*v.clone().get_try().await.expect("ok"), 3);
    }

    #[test_log::test(tokio::test)]
    async fn sanity_jit_try_err() {
        let v = JitTry::new_try(|| async {
            fedimint_core::runtime::sleep(Duration::from_millis(0)).await;
            bail!("BOOM");
            #[allow(unreachable_code)]
            Ok(3)
        });

        assert!(v.get_try().await.is_err());
        assert!(v.get_try().await.is_err());
        assert!(v.clone().get_try().await.is_err());
    }
}
