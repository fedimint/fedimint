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
fn test_safe_url_join_path() {
    let base = SafeUrl::parse("http://admin:secret@127.0.0.1:8080/api/v1").unwrap();
    let joined = base.join_path("users");
    assert_eq!(joined.as_str(), "http://admin:secret@127.0.0.1:8080/api/v1/users");
    assert_eq!(joined.username(), "admin");
    assert_eq!(joined.password(), Some("secret"));
    assert_eq!(format!("{joined}"), "http://REDACTEDUSER:REDACTEDPASS@127.0.0.1:8080/api/v1/users");

    let base_with_trailing = SafeUrl::parse("http://admin:secret@127.0.0.1:8080/api/v1/").unwrap();
    let joined = base_with_trailing.join_path("/users/profile/");
    assert_eq!(joined.as_str(), "http://admin:secret@127.0.0.1:8080/api/v1/users/profile/");
    assert_eq!(joined.username(), "admin");
    assert_eq!(joined.password(), Some("secret"));

    let with_empty_segment = base.join_path("foo//bar");
    assert_eq!(with_empty_segment.as_str(), "http://admin:secret@127.0.0.1:8080/api/v1/foo//bar");

    let root = SafeUrl::parse("http://127.0.0.1:8080").unwrap();
    assert_eq!(root.join_path("foo").as_str(), "http://127.0.0.1:8080/foo");
    assert_eq!(root.join_path("/foo/bar").as_str(), "http://127.0.0.1:8080/foo/bar");
    assert_eq!(root.join_path("").as_str(), "http://127.0.0.1:8080/");

    let with_query_frag = SafeUrl::parse("http://127.0.0.1:8080/base?key=value#frag").unwrap();
    let joined = with_query_frag.join_path("sub");
    assert_eq!(joined.as_str(), "http://127.0.0.1:8080/base/sub?key=value#frag");
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
