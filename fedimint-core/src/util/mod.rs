/// Copied from `tokio_stream` 0.1.12 to use our optional Send bounds
pub mod broadcaststream;

use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::hash::Hash;
use std::io::Write;
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::{fs, io};

use anyhow::format_err;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tracing::debug;
use url::{Host, ParseError, Url};

use crate::task::MaybeSend;
use crate::{apply, async_trait_maybe_send, maybe_add_send};

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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fedimint_core::task::Elapsed;
    use futures::FutureExt;

    use crate::task::timeout;
    use crate::util::{NextOrPending, SafeUrl};

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
}
