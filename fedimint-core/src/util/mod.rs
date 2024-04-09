/// Copied from `tokio_stream` 0.1.12 to use our optional Send bounds
pub mod broadcaststream;
pub mod update_merge;

use std::convert::Infallible;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::hash::Hash;
use std::io::Write;
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::{fs, io};

use anyhow::format_err;
use fedimint_logging::LOG_CORE;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn, Instrument, Span};
use url::{Host, ParseError, Url};

use crate::task::MaybeSend;
use crate::{apply, async_trait_maybe_send, maybe_add_send, runtime};

/// Future that is `Send` unless targeting WASM
pub type BoxFuture<'a, T> = Pin<Box<maybe_add_send!(dyn Future<Output = T> + 'a)>>;

/// Stream that is `Send` unless targeting WASM
pub type BoxStream<'a, T> = Pin<Box<maybe_add_send!(dyn futures::Stream<Item = T> + 'a)>>;

#[apply(async_trait_maybe_send!)]
pub trait NextOrPending {
    type Output;

    async fn next_or_pending(&mut self) -> Self::Output;

    async fn ok(&mut self) -> anyhow::Result<Self::Output>;
}

#[apply(async_trait_maybe_send!)]
impl<S> NextOrPending for S
where
    S: futures::Stream + Unpin + MaybeSend,
    S::Item: MaybeSend,
{
    type Output = S::Item;

    /// Waits for the next item in a stream. If the stream is closed while
    /// waiting, returns an error.  Useful when expecting a stream to progress.
    async fn ok(&mut self) -> anyhow::Result<Self::Output> {
        match self.next().await {
            Some(item) => Ok(item),
            None => Err(format_err!("Stream was unexpectedly closed")),
        }
    }

    /// Waits for the next item in a stream. If the stream is closed while
    /// waiting the future will be pending forever. This is useful in cases
    /// where the future will be cancelled by shutdown logic anyway and handling
    /// each place where a stream may terminate would be too much trouble.
    async fn next_or_pending(&mut self) -> Self::Output {
        match self.next().await {
            Some(item) => item,
            None => {
                debug!("Stream ended in next_or_pending, pending forever to avoid throwing an error on shutdown");
                std::future::pending().await
            }
        }
    }
}

// TODO: make fully RFC1738 conformant
/// Wrapper for `Url` that only prints the scheme, domain, port and path portion
/// of a `Url` in its `Display` implementation. This is useful to hide private
/// information like user names and passwords in logs or UIs.
///
/// The output is not fully RFC1738 conformant but good enough for our current
/// purposes.
#[derive(Hash, Clone, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
// nosemgrep: ban-raw-url
pub struct SafeUrl(Url);

impl SafeUrl {
    pub fn parse(url_str: &str) -> Result<SafeUrl, ParseError> {
        Url::parse(url_str).map(SafeUrl)
    }

    /// Warning: This removes the safety.
    // nosemgrep: ban-raw-url
    pub fn to_unsafe(self) -> Url {
        self.0
    }

    pub fn host(&self) -> Option<Host<&str>> {
        self.0.host()
    }
    pub fn host_str(&self) -> Option<&str> {
        self.0.host_str()
    }
    pub fn scheme(&self) -> &str {
        self.0.scheme()
    }
    pub fn port(&self) -> Option<u16> {
        self.0.port()
    }
    pub fn port_or_known_default(&self) -> Option<u16> {
        self.0.port_or_known_default()
    }
    pub fn path(&self) -> &str {
        self.0.path()
    }
    /// Warning: This will expose username & password if present.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    pub fn username(&self) -> &str {
        self.0.username()
    }
    pub fn password(&self) -> Option<&str> {
        self.0.password()
    }
    pub fn join(&self, input: &str) -> Result<SafeUrl, ParseError> {
        self.0.join(input).map(SafeUrl)
    }
}

impl Display for SafeUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://", self.0.scheme())?;

        if let Some(host) = self.0.host_str() {
            write!(f, "{host}")?;
        }

        if let Some(port) = self.0.port() {
            write!(f, ":{port}")?;
        }

        write!(f, "{}", self.0.path())?;

        Ok(())
    }
}

impl Debug for SafeUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SafeUrl(")?;
        Display::fmt(self, f)?;
        write!(f, ", has_password={}", self.0.password().is_some())?;
        write!(f, ", has_username={}", !self.0.username().is_empty())?;
        write!(f, ")")?;
        Ok(())
    }
}

/// Only ease conversions from unsafe into safe version.
/// We want to protect leakage of sensitive credentials unless code explicitly
/// calls `to_unsafe()`.
impl From<Url> for SafeUrl {
    fn from(u: Url) -> Self {
        SafeUrl(u)
    }
}

impl FromStr for SafeUrl {
    type Err = ParseError;

    #[inline]
    fn from_str(input: &str) -> Result<SafeUrl, ParseError> {
        SafeUrl::parse(input)
    }
}

/// Write out a new file (like [`std::fs::write`] but fails if file already
/// exists)
#[cfg(not(target_family = "wasm"))]
pub fn write_new<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    fs::File::options()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(contents.as_ref())
}

#[cfg(not(target_family = "wasm"))]
pub fn write_overwrite<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    fs::File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?
        .write_all(contents.as_ref())
}

#[cfg(not(target_family = "wasm"))]
pub async fn write_overwrite_async<P: AsRef<Path>, C: AsRef<[u8]>>(
    path: P,
    contents: C,
) -> io::Result<()> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .await?
        .write_all(contents.as_ref())
        .await
}

#[cfg(not(target_family = "wasm"))]
pub async fn write_new_async<P: AsRef<Path>, C: AsRef<[u8]>>(
    path: P,
    contents: C,
) -> io::Result<()> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await?
        .write_all(contents.as_ref())
        .await
}

#[derive(Debug, Clone)]
pub struct Spanned<T> {
    value: T,
    span: Span,
}

impl<T> Spanned<T> {
    pub async fn new<F: Future<Output = T>>(span: Span, make: F) -> Self {
        Self::try_new::<Infallible, _>(span, async { Ok(make.await) })
            .await
            .unwrap()
    }

    pub async fn try_new<E, F: Future<Output = Result<T, E>>>(
        span: Span,
        make: F,
    ) -> Result<Self, E> {
        let span2 = span.clone();
        async move {
            Ok(Self {
                value: make.await?,
                span: span2,
            })
        }
        .instrument(span)
        .await
    }

    pub fn borrow(&self) -> Spanned<&T> {
        Spanned {
            value: &self.value,
            span: self.span.clone(),
        }
    }

    pub fn map<U>(self, map: impl Fn(T) -> U) -> Spanned<U> {
        Spanned {
            value: map(self.value),
            span: self.span.clone(),
        }
    }

    pub async fn borrow_mut(&mut self) -> Spanned<&mut T> {
        Spanned {
            value: &mut self.value,
            span: self.span.clone(),
        }
    }

    pub fn with_sync<O, F: FnOnce(T) -> O>(self, f: F) -> O {
        let _g = self.span.enter();
        f(self.value)
    }

    pub async fn with<Fut: Future, F: FnOnce(T) -> Fut>(self, f: F) -> Fut::Output {
        async { f(self.value).await }.instrument(self.span).await
    }

    pub fn span(&self) -> Span {
        self.span.clone()
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    pub fn into_value(self) -> T {
        self.value
    }
}

/// For CLIs, detects `version-hash` as a single argument, prints the provided
/// version hash, then exits the process.
pub fn handle_version_hash_command(version_hash: &str) {
    let mut args = std::env::args();
    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", version_hash);
            std::process::exit(0);
        }
    }
}

pub use backon::{
    BackoffBuilder, ConstantBuilder as ConstantBackoff, ExponentialBuilder as ExponentialBackoff,
    FibonacciBuilder as FibonacciBackoff,
};

/// Run the supplied closure `op_fn` until it succeeds. Frequency and number of
/// retries is determined by the specified strategy.
///
/// ```
/// use std::time::Duration;
///
/// use fedimint_core::util::{retry, FibonacciBackoff};
/// # tokio_test::block_on(async {
/// retry(
///     "Gateway balance after swap".to_string(),
///     FibonacciBackoff::default()
///         .with_min_delay(Duration::from_millis(200))
///         .with_max_delay(Duration::from_secs(3))
///         .with_max_times(10),
///     || async {
///         // Fallible network calls …
///         Ok(())
///     },
/// )
/// .await
/// .expect("never fails");
/// # });
/// ```
///
/// # Returns
///
/// - If the closure runs successfully, the result is immediately returned
/// - If the closure did not run successfully for `max_attempts` times, the
///   error of the closure is returned
pub async fn retry<F, Fut, T>(
    op_name: impl Into<String>,
    strategy: impl backon::BackoffBuilder,
    op_fn: F,
) -> Result<T, anyhow::Error>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, anyhow::Error>>,
{
    let mut strategy = strategy.build();
    let op_name = op_name.into();
    let mut attempts = 0;
    loop {
        attempts += 1;
        match op_fn().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                if let Some(interval) = strategy.next() {
                    // run closure op_fn again
                    debug!(
                        target: LOG_CORE,
                        %error,
                        %attempts,
                        interval = interval.as_secs(),
                        "{} failed, retrying",
                        op_name,
                    );
                    runtime::sleep(interval).await;
                } else {
                    warn!(
                        target: LOG_CORE,
                        %error,
                        %attempts,
                        "{} failed",
                        op_name,
                    );
                    return Err(error);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::time::Duration;

    use anyhow::anyhow;
    use fedimint_core::runtime::Elapsed;
    use futures::FutureExt;

    use super::*;
    use crate::runtime::timeout;

    #[test]
    fn test_safe_url() {
        let test_cases = vec![
            (
                "http://1.2.3.4:80/foo",
                "http://1.2.3.4/foo",
                "SafeUrl(http://1.2.3.4/foo, has_password=false, has_username=false)",
            ),
            (
                "http://1.2.3.4:81/foo",
                "http://1.2.3.4:81/foo",
                "SafeUrl(http://1.2.3.4:81/foo, has_password=false, has_username=false)",
            ),
            (
                "fedimint://1.2.3.4:1000/foo",
                "fedimint://1.2.3.4:1000/foo",
                "SafeUrl(fedimint://1.2.3.4:1000/foo, has_password=false, has_username=false)",
            ),
            (
                "fedimint://foo:bar@domain.com:1000/foo",
                "fedimint://domain.com:1000/foo",
                "SafeUrl(fedimint://domain.com:1000/foo, has_password=true, has_username=true)",
            ),
            (
                "fedimint://foo@1.2.3.4:1000/foo",
                "fedimint://1.2.3.4:1000/foo",
                "SafeUrl(fedimint://1.2.3.4:1000/foo, has_password=false, has_username=true)",
            ),
        ];

        for (url_str, safe_display_expected, safe_debug_expected) in test_cases {
            let safe_url = SafeUrl::parse(url_str).unwrap();

            let safe_display = format!("{safe_url}");
            assert_eq!(
                safe_display, safe_display_expected,
                "Display implementation out of spec"
            );

            let safe_debug = format!("{safe_url:?}");
            assert_eq!(
                safe_debug, safe_debug_expected,
                "Debug implementation out of spec"
            );
        }

        // Exercise `From`-trait via `Into`
        let _: SafeUrl = url::Url::parse("http://1.2.3.4:80/foo").unwrap().into();
    }

    #[tokio::test]
    async fn test_next_or_pending() {
        let mut stream = futures::stream::iter(vec![1, 2]);
        assert_eq!(stream.next_or_pending().now_or_never(), Some(1));
        assert_eq!(stream.next_or_pending().now_or_never(), Some(2));
        assert!(matches!(
            timeout(Duration::from_millis(100), stream.next_or_pending()).await,
            Err(Elapsed)
        ));
    }
    #[tokio::test]
    async fn retry_succeed_with_one_attempt() {
        let counter = AtomicU8::new(0);
        let closure = || async {
            counter.fetch_add(1, Ordering::SeqCst);
            // always return a success
            Ok(42)
        };

        let _ = retry(
            "Run once",
            ConstantBackoff::default()
                .with_delay(Duration::ZERO)
                .with_max_times(3),
            closure,
        )
        .await;

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retry_fail_with_three_attempts() {
        let counter = AtomicU8::new(0);
        let closure = || async {
            counter.fetch_add(1, Ordering::SeqCst);
            // always fail
            Err::<(), anyhow::Error>(anyhow!("42"))
        };

        let _ = retry(
            "Run 3 once",
            ConstantBackoff::default()
                .with_delay(Duration::ZERO)
                // retry two error
                .with_max_times(2),
            closure,
        )
        .await;

        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }
}
