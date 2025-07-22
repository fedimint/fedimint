use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use anyhow::anyhow;
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
fn test_percent_encoding_safe_url() {
    let url =
        SafeUrl::parse("http://user=name:p@ssword@127.0.0.1:80").expect("Could not parse safe url");
    assert_eq!(url.username(), "user=name".to_string());
    assert_eq!(url.password().expect("No password"), "p@ssword");
}

#[tokio::test]
async fn test_next_or_pending() {
    let mut stream = futures::stream::iter(vec![1, 2]);
    assert_eq!(stream.next_or_pending().now_or_never(), Some(1));
    assert_eq!(stream.next_or_pending().now_or_never(), Some(2));
    assert!(matches!(
        timeout(Duration::from_millis(100), stream.next_or_pending()).await,
        Err(Elapsed { .. })
    ));
}

#[tokio::test]
async fn retry_succeed_with_one_attempt() {
    let counter = AtomicU8::new(0);
    let closure = || async {
        counter.fetch_add(1, Ordering::SeqCst);
        // Always return a success.
        Ok(42)
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
        Err::<(), anyhow::Error>(anyhow!("42"))
    };

    let _ = retry(
        "Run 3 times",
        backoff_util::immediate_backoff(Some(2)),
        closure,
    )
    .await;

    assert_eq!(counter.load(Ordering::SeqCst), 3);
}
