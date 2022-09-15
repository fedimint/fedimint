use async_trait::async_trait;
use std::future::Future;

#[async_trait(?Send)]
pub trait ThenAsync {
    /// Run the supplied future is `self == true` and return its output, `None` otherwise
    async fn then_async<F, O>(&self, f: F) -> Option<O>
    where
        F: Future<Output = O>;
}

#[async_trait(?Send)]
impl ThenAsync for bool {
    async fn then_async<F, O>(&self, f: F) -> Option<O>
    where
        F: Future<Output = O>,
    {
        if *self {
            Some(f.await)
        } else {
            None
        }
    }
}

#[async_trait(?Send)]
pub trait UnwrapOrElseAsync {
    type Output;

    async fn unwrap_or_else_async<F>(self, f: F) -> Self::Output
    where
        F: Future<Output = Self::Output>;
}

#[async_trait(?Send)]
impl<T> UnwrapOrElseAsync for Option<T> {
    type Output = T;

    async fn unwrap_or_else_async<F>(self, f: F) -> Self::Output
    where
        F: Future<Output = Self::Output>,
    {
        match self {
            Some(x) => x,
            None => f.await,
        }
    }
}
