use std::cell::Cell;
use std::future::{pending, ready};
use std::time::Duration;

use fedimint_core::secp256k1::PublicKey;
use serde_json::json;

use super::wait_for_lightning_pubkey;

const PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

#[tokio::test]
async fn waits_for_a_public_key_in_either_response_format() {
    for [disconnected, connected] in [
        [
            json!({"lightning_info": "not_connected"}),
            json!({"lightning_info": {"connected": {"public_key": PUBKEY}}}),
        ],
        [
            json!({"lightning_pub_key": null}),
            json!({"lightning_pub_key": PUBKEY}),
        ],
    ] {
        let first = Cell::new(true);
        let key = wait_for_lightning_pubkey(Duration::from_secs(5), || {
            ready(Ok(if first.replace(false) {
                disconnected.clone()
            } else {
                connected.clone()
            }))
        })
        .await
        .unwrap();
        assert_eq!(key, PUBKEY.parse::<PublicKey>().unwrap());
    }
}

#[tokio::test]
async fn fails_without_retrying_malformed_responses() {
    for (response, field) in [
        (json!({}), "lightning_pub_key"),
        (json!({"lightning_pub_key": 7}), "lightning_pub_key"),
        (
            json!({"lightning_info": "unexpected"}),
            "lightning_info.connected.public_key",
        ),
        (
            json!({"lightning_info": {"connected": {}}}),
            "lightning_info.connected.public_key",
        ),
        (
            json!({"lightning_info": {"connected": {}}, "lightning_pub_key": PUBKEY}),
            "lightning_info.connected.public_key",
        ),
        (
            json!({"lightning_info": {"connected": {"public_key": null}}}),
            "lightning_info.connected.public_key",
        ),
        (
            json!({"lightning_info": {"connected": {"public_key": "invalid-key"}}}),
            "lightning_info.connected.public_key",
        ),
    ] {
        let attempts = Cell::new(0);
        let error = wait_for_lightning_pubkey(Duration::from_secs(5), || {
            attempts.set(attempts.get() + 1);
            ready(Ok(response.clone()))
        })
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(attempts.get(), 1);
        assert!(error.contains(field), "{error}");
        assert!(!error.contains("invalid-key"), "{error}");
    }
}

#[tokio::test]
async fn does_not_retry_a_failed_info_call() {
    let attempts = Cell::new(0);
    let error = wait_for_lightning_pubkey(Duration::from_secs(5), || {
        attempts.set(attempts.get() + 1);
        ready(Err(anyhow::anyhow!("info failed")))
    })
    .await
    .unwrap_err();
    assert_eq!(attempts.get(), 1);
    assert_eq!(error.to_string(), "info failed");
}

#[tokio::test]
async fn times_out_if_disconnected_or_info_does_not_return() {
    let timeout = Duration::from_millis(20);
    let disconnected = wait_for_lightning_pubkey(timeout, || {
        ready(Ok(json!({"lightning_info": "not_connected"})))
    })
    .await
    .unwrap_err();
    let hung = wait_for_lightning_pubkey(timeout, pending)
        .await
        .unwrap_err();
    for error in [disconnected, hung] {
        assert!(error.to_string().contains("Timed out"));
    }
}
