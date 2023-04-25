/// Copied from `tokio_stream` 0.1.12 to use our optional Send bounds
pub mod broadcaststream;

use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::io::Write;
use std::path::Path;
use std::pin::Pin;
use std::{fs, io};

use futures::StreamExt;
use tracing::debug;
use url::Url;

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
}

#[apply(async_trait_maybe_send!)]
impl<S> NextOrPending for S
where
    S: futures::Stream + Unpin + MaybeSend,
    S::Item: MaybeSend,
{
    type Output = S::Item;

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
pub struct SanitizedUrl<'a>(Cow<'a, Url>);

impl<'a> SanitizedUrl<'a> {
    pub fn new_owned(url: Url) -> SanitizedUrl<'static> {
        SanitizedUrl(Cow::Owned(url))
    }

    pub fn new_borrowed(url: &'a Url) -> SanitizedUrl<'a> {
        SanitizedUrl(Cow::Borrowed(url))
    }
}

impl<'a> Display for SanitizedUrl<'a> {
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

impl<'a> Debug for SanitizedUrl<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SanitizedUrl(")?;
        Display::fmt(self, f)?;
        write!(f, ", has_password={}", self.0.password().is_some())?;
        write!(f, ", has_username={}", !self.0.username().is_empty())?;
        write!(f, ")")?;
        Ok(())
    }
}

/// Write out a new file (like [`std::fs::write`] but fails if file already
/// exists)
pub fn write_new<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    fs::File::options()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(contents.as_ref())
}

pub fn write_overwrite<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    fs::File::options()
        .write(true)
        .create(true)
        .open(path)?
        .write_all(contents.as_ref())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fedimint_core::task::Elapsed;
    use futures::FutureExt;
    use url::Url;

    use crate::task::timeout;
    use crate::util::{NextOrPending, SanitizedUrl};

    #[test]
    fn test_sanitized_url() {
        let test_cases = vec![
            ("http://1.2.3.4:80/foo", "http://1.2.3.4/foo", "SanitizedUrl(http://1.2.3.4/foo, has_password=false, has_username=false)"),
            ("http://1.2.3.4:81/foo", "http://1.2.3.4:81/foo", "SanitizedUrl(http://1.2.3.4:81/foo, has_password=false, has_username=false)"),
            ("fedimint://1.2.3.4:1000/foo", "fedimint://1.2.3.4:1000/foo", "SanitizedUrl(fedimint://1.2.3.4:1000/foo, has_password=false, has_username=false)"),
            ("fedimint://foo:bar@domain.com:1000/foo", "fedimint://domain.com:1000/foo", "SanitizedUrl(fedimint://domain.com:1000/foo, has_password=true, has_username=true)"),
            ("fedimint://foo@1.2.3.4:1000/foo", "fedimint://1.2.3.4:1000/foo", "SanitizedUrl(fedimint://1.2.3.4:1000/foo, has_password=false, has_username=true)"),
        ];

        for (url_str, sanitized_display_expected, sanitized_debug_expected) in test_cases {
            let url = Url::parse(url_str).unwrap();
            let sanitized_url = SanitizedUrl::new_borrowed(&url);

            let sanitized_display = format!("{sanitized_url}");
            assert_eq!(
                sanitized_display, sanitized_display_expected,
                "Display implementation out of spec"
            );

            let sanitized_debug = format!("{sanitized_url:?}");
            assert_eq!(
                sanitized_debug, sanitized_debug_expected,
                "Debug implementation out of spec"
            );
        }
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
