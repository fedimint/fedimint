pub mod backoff_util;
/// Copied from `tokio_stream` 0.1.12 to use our optional Send bounds
pub mod broadcaststream;
mod error;
pub mod update_merge;

use std::convert::Infallible;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::hash::Hash;
use std::io::Write;
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::LazyLock;
use std::{fs, io};

use anyhow::format_err;
pub use error::*;
use fedimint_logging::LOG_CORE;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tracing::{Instrument, Span, debug, warn};
use url::{Host, ParseError, Url};

use crate::envs::{FM_DEBUG_SHOW_SECRETS_ENV, is_env_var_set};
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
        self.next()
            .await
            .map_or_else(|| Err(format_err!("Stream was unexpectedly closed")), Ok)
    }

    /// Waits for the next item in a stream. If the stream is closed while
    /// waiting the future will be pending forever. This is useful in cases
    /// where the future will be cancelled by shutdown logic anyway and handling
    /// each place where a stream may terminate would be too much trouble.
    async fn next_or_pending(&mut self) -> Self::Output {
        if let Some(item) = self.next().await {
            item
        } else {
            debug!(target: LOG_CORE, "Stream ended in next_or_pending, pending forever to avoid throwing an error on shutdown");
            std::future::pending().await
        }
    }
}

// TODO: make fully RFC1738 conformant
/// Wrapper for `Url` that only prints the scheme, domain, port and path portion
/// of a `Url` in its `Display` implementation.
///
/// This is useful to hide private
/// information like user names and passwords in logs or UIs.
///
/// The output is not fully RFC1738 conformant but good enough for our current
/// purposes.
#[derive(Hash, Clone, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
// nosemgrep: ban-raw-url
pub struct SafeUrl(Url);

impl SafeUrl {
    pub fn parse(url_str: &str) -> Result<Self, ParseError> {
        Url::parse(url_str).map(SafeUrl)
    }

    /// Warning: This removes the safety.
    // nosemgrep: ban-raw-url
    pub fn to_unsafe(self) -> Url {
        self.0
    }

    #[allow(clippy::result_unit_err)] // just copying `url`'s API here
    pub fn set_username(&mut self, username: &str) -> Result<(), ()> {
        self.0.set_username(username)
    }

    #[allow(clippy::result_unit_err)] // just copying `url`'s API here
    pub fn set_password(&mut self, password: Option<&str>) -> Result<(), ()> {
        self.0.set_password(password)
    }

    #[allow(clippy::result_unit_err)] // just copying `url`'s API here
    pub fn without_auth(&self) -> Result<Self, ()> {
        let mut url = self.clone();

        url.set_username("").and_then(|()| url.set_password(None))?;

        Ok(url)
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
    pub fn join(&self, input: &str) -> Result<Self, ParseError> {
        self.0.join(input).map(SafeUrl)
    }

    // It can be removed to use `is_onion_address()` implementation,
    // once https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2214 lands.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    pub fn is_onion_address(&self) -> bool {
        let host = self.host_str().unwrap_or_default();

        host.ends_with(".onion")
    }

    pub fn fragment(&self) -> Option<&str> {
        self.0.fragment()
    }

    pub fn set_fragment(&mut self, arg: Option<&str>) {
        self.0.set_fragment(arg);
    }
}

static SHOW_SECRETS: LazyLock<bool> = LazyLock::new(|| {
    let enable = is_env_var_set(FM_DEBUG_SHOW_SECRETS_ENV);

    if enable {
        warn!(target: LOG_CORE, "{} enabled. Please don't use in production.", FM_DEBUG_SHOW_SECRETS_ENV);
    }

    enable
});

impl Display for SafeUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://", self.0.scheme())?;

        if !self.0.username().is_empty() {
            let show_secrets = *SHOW_SECRETS;
            if show_secrets {
                write!(f, "{}", self.0.username())?;
            } else {
                write!(f, "REDACTEDUSER")?;
            }

            if self.0.password().is_some() {
                if show_secrets {
                    write!(
                        f,
                        ":{}",
                        self.0.password().expect("Just checked it's checked")
                    )?;
                } else {
                    write!(f, ":REDACTEDPASS")?;
                }
            }

            write!(f, "@")?;
        }

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
        write!(f, ")")?;
        Ok(())
    }
}

impl From<Url> for SafeUrl {
    fn from(u: Url) -> Self {
        Self(u)
    }
}

impl FromStr for SafeUrl {
    type Err = ParseError;

    #[inline]
    fn from_str(input: &str) -> Result<Self, ParseError> {
        Self::parse(input)
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
        async {
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
            span: self.span,
        }
    }

    pub fn borrow_mut(&mut self) -> Spanned<&mut T> {
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
            println!("{version_hash}");
            std::process::exit(0);
        }
    }
}

/// Run the supplied closure `op_fn` until it succeeds. Frequency and number of
/// retries is determined by the specified strategy.
///
/// ```
/// use std::time::Duration;
///
/// use fedimint_core::util::{backoff_util, retry};
/// # tokio_test::block_on(async {
/// retry(
///     "Gateway balance after swap".to_string(),
///     backoff_util::background_backoff(),
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
    strategy: impl backoff_util::Backoff,
    op_fn: F,
) -> Result<T, anyhow::Error>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, anyhow::Error>>,
{
    let mut strategy = strategy;
    let op_name = op_name.into();
    let mut attempts: u64 = 0;
    loop {
        attempts += 1;
        match op_fn().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                if let Some(interval) = strategy.next() {
                    // run closure op_fn again
                    debug!(
                        target: LOG_CORE,
                        err = %err.fmt_compact_anyhow(),
                        %attempts,
                        interval = interval.as_secs(),
                        "{} failed, retrying",
                        op_name,
                    );
                    runtime::sleep(interval).await;
                } else {
                    warn!(
                        target: LOG_CORE,
                        err = %err.fmt_compact_anyhow(),
                        %attempts,
                        "{} failed",
                        op_name,
                    );
                    return Err(err);
                }
            }
        }
    }
}

/// Computes the median from a slice of sorted `u64`s
pub fn get_median(vals: &[u64]) -> Option<u64> {
    if vals.is_empty() {
        return None;
    }
    let len = vals.len();
    let mid = len / 2;

    if len % 2 == 0 {
        Some(u64::midpoint(vals[mid - 1], vals[mid]))
    } else {
        Some(vals[mid])
    }
}

/// Computes the average of the given `u64` slice.
pub fn get_average(vals: &[u64]) -> Option<u64> {
    if vals.is_empty() {
        return None;
    }

    let sum: u64 = vals.iter().sum();
    Some(sum / vals.len() as u64)
}

#[cfg(test)]
mod tests;
