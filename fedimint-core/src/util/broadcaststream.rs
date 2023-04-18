use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::broadcast::Receiver;

use crate::task::MaybeSend;
use crate::util::BoxFuture;

/// A wrapper around [`tokio::sync::broadcast::Receiver`] that implements
/// [`Stream`].
///
/// [`tokio::sync::broadcast::Receiver`]: struct@tokio::sync::broadcast::Receiver
/// [`Stream`]: trait@futures::Stream
#[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
pub struct BroadcastStream<T> {
    inner: BoxFuture<'static, (Result<T, RecvError>, Receiver<T>)>,
}

/// An error returned from the inner stream of a [`BroadcastStream`].
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BroadcastStreamRecvError {
    /// The receiver lagged too far behind. Attempting to receive again will
    /// return the oldest message still retained by the channel.
    ///
    /// Includes the number of skipped messages.
    Lagged(u64),
}

impl fmt::Display for BroadcastStreamRecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BroadcastStreamRecvError::Lagged(amt) => write!(f, "channel lagged by {amt}"),
        }
    }
}

impl std::error::Error for BroadcastStreamRecvError {}

async fn make_future<T: Clone>(mut rx: Receiver<T>) -> (Result<T, RecvError>, Receiver<T>) {
    let result = rx.recv().await;
    (result, rx)
}

impl<T: 'static + Clone + MaybeSend> BroadcastStream<T> {
    /// Create a new `BroadcastStream`.
    pub fn new(rx: Receiver<T>) -> Self {
        Self {
            inner: Box::pin(make_future(rx)),
        }
    }
}

impl<T: 'static + Clone + MaybeSend> Stream for BroadcastStream<T> {
    type Item = Result<T, BroadcastStreamRecvError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (result, rx) = ready!(Pin::new(&mut self.inner).poll(cx));
        self.inner = Box::pin(make_future(rx));
        match result {
            Ok(item) => Poll::Ready(Some(Ok(item))),
            Err(RecvError::Closed) => Poll::Ready(None),
            Err(RecvError::Lagged(n)) => {
                Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(n))))
            }
        }
    }
}

impl<T> fmt::Debug for BroadcastStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BroadcastStream").finish()
    }
}

impl<T: 'static + Clone + MaybeSend> From<Receiver<T>> for BroadcastStream<T> {
    fn from(recv: Receiver<T>) -> Self {
        Self::new(recv)
    }
}
