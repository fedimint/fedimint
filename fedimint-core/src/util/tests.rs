use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use assert_matches::assert_matches;
use fedimint_core::runtime::Elapsed;
use futures::FutureExt;

use super::{NextOrPending, SafeUrl, backoff_util, retry};
use crate::runtime::timeout;

#[test]
fn test_safe_url() {
    let test_cases = vec![
        (
            "http://1.2.3.4:80/foo",
            "http://1.2.3.4/foo",
            "SafeUrl(http://1.2.3.4/foo)",
            "http://1.2.3.4/foo",
        ),
        (
            "http://1.2.3.4:81/foo",
            "http://1.2.3.4:81/foo",
            "SafeUrl(http://1.2.3.4:81/foo)",
            "http://1.2.3.4:81/foo",
        ),
        (
            "fedimint://1.2.3.4:1000/foo",
            "fedimint://1.2.3.4:1000/foo",
            "SafeUrl(fedimint://1.2.3.4:1000/foo)",
            "fedimint://1.2.3.4:1000/foo",
        ),
        (
            "fedimint://foo:bar@domain.com:1000/foo",
            "fedimint://REDACTEDUSER:REDACTEDPASS@domain.com:1000/foo",
            "SafeUrl(fedimint://REDACTEDUSER:REDACTEDPASS@domain.com:1000/foo)",
            "fedimint://domain.com:1000/foo",
        ),
        (
            "fedimint://foo@1.2.3.4:1000/foo",
            "fedimint://REDACTEDUSER@1.2.3.4:1000/foo",
            "SafeUrl(fedimint://REDACTEDUSER@1.2.3.4:1000/foo)",
            "fedimint://1.2.3.4:1000/foo",
        ),
    ];

    for (url_str, safe_display_expected, safe_debug_expected, without_auth_expected) in test_cases {
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

        let without_auth = safe_url.without_auth().unwrap();
        assert_eq!(
            without_auth.as_str(),
            without_auth_expected,
            "Without auth implementation out of spec"
        );
    }

    // Exercise `From`-trait via `Into`
    let _: SafeUrl = url::Url::parse("http://1.2.3.4:80/foo").unwrap().into();
}

#[test]
fn join_path_preserves_credentials_query_and_fragment() {
    let base = SafeUrl::parse("https://alice:s3cret@example.com:8443/api/v1?x=1#frag").unwrap();
    let joined = base.join_path("lnv1/paycodes");

    assert_eq!(joined.username(), "alice");
    assert_eq!(joined.password(), Some("s3cret"));
    assert_eq!(joined.path(), "/api/v1/lnv1/paycodes");
    assert_eq!(
        joined.as_str(),
        "https://alice:s3cret@example.com:8443/api/v1/lnv1/paycodes?x=1#frag"
    );
    // Display still redacts secrets
    assert_eq!(
        format!("{joined}"),
        "https://REDACTEDUSER:REDACTEDPASS@example.com:8443/api/v1/lnv1/paycodes"
    );
}

#[test]
fn join_path_appends_and_normalizes_slashes() {
    let base = SafeUrl::parse("http://1.2.3.4:81/foo/").unwrap();
    assert_eq!(base.join_path("bar").as_str(), "http://1.2.3.4:81/foo/bar");
    assert_eq!(base.join_path("/bar").as_str(), "http://1.2.3.4:81/foo/bar");
    assert_eq!(
        base.join_path("bar/baz").as_str(),
        "http://1.2.3.4:81/foo/bar/baz"
    );
    assert_eq!(
        base.join_path("//bar//").as_str(),
        "http://1.2.3.4:81/foo/bar"
    );

    let root = SafeUrl::parse("http://1.2.3.4/").unwrap();
    assert_eq!(root.join_path("x").as_str(), "http://1.2.3.4/x");

    // Multiple trailing slashes on the base must collapse like the old
    // Display + trim_end_matches('/') path (not leave `/api///lnv1`).
    let multi = SafeUrl::parse("http://1.2.3.4/api///").unwrap();
    assert_eq!(multi.join_path("lnv1").as_str(), "http://1.2.3.4/api/lnv1");
}

#[tokio::test]
async fn test_next_or_pending() {
    let mut stream = futures::stream::iter(vec![1, 2]);
    assert_eq!(stream.next_or_pending().now_or_never(), Some(1));
    assert_eq!(stream.next_or_pending().now_or_never(), Some(2));
    assert_matches!(
        timeout(Duration::from_millis(100), stream.next_or_pending()).await,
        Err(Elapsed { .. })
    );
}

#[tokio::test]
async fn retry_succeed_with_one_attempt() {
    let counter = AtomicU8::new(0);
    let closure = || async {
        counter.fetch_add(1, Ordering::SeqCst);
        // Always return a success.
        Ok::<_, std::io::Error>(42)
    };

    let _ = retry(
        "Run once",
        backoff_util::immediate_backoff(Some(2)),
        closure,
    )
    .await;

    // Ensure the closure was only called once, and no backoff was applied.
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn retry_fail_with_three_attempts() {
    let counter = AtomicU8::new(0);
    let closure = || async {
        counter.fetch_add(1, Ordering::SeqCst);
        // always fail
        Err::<(), _>(std::io::Error::other("42"))
    };

    let _ = retry(
        "Run 3 times",
        backoff_util::immediate_backoff(Some(2)),
        closure,
    )
    .await;

    assert_eq!(counter.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn ok_reports_closed_stream_with_typed_error() {
    let mut stream = futures::stream::iter(vec![1]);
    assert_eq!(stream.ok().await, Ok(1));
    assert_eq!(stream.ok().await, Err(super::StreamEndedError));
}

#[tokio::test]
async fn retry_keeps_the_closure_error_type() {
    #[derive(Debug, PartialEq, thiserror::Error)]
    #[error("Nope")]
    struct Nope;

    let result: Result<(), Nope> = retry(
        "always fails",
        backoff_util::immediate_backoff(Some(2)),
        || async { Err(Nope) },
    )
    .await;
    assert_eq!(result, Err(Nope));
}
