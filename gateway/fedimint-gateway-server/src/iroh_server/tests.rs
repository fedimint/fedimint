use anyhow::anyhow;
use axum::Json;
use bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::module::GATEWAY_ERROR_RESPONSE_VERSION;
use reqwest::StatusCode;

use super::{parse_verify_route, run_handler};
use crate::error::{GatewayError, PublicGatewayError};

#[tokio::test]
async fn federation_unreachable_handler_returns_sanitized_error() {
    let (status, body) = run_handler("/pay_invoice", async {
        Err::<(StatusCode, Json<serde_json::Value>), _>(
            GatewayError::Public(PublicGatewayError::FederationUnreachable).into(),
        )
    })
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body.0,
        serde_json::json!({
            "version": GATEWAY_ERROR_RESPONSE_VERSION,
            "error": "federation_unreachable"
        })
    );
    assert!(!body.0.to_string().contains("sensitive-debug-sentinel"));
}

#[tokio::test]
async fn panicking_handler_returns_an_error_instead_of_unwinding() {
    let (status, _body) = run_handler("/pay_invoice", async { panic!("handler panic") }).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn failing_handler_is_answered_instead_of_ending_the_connection() {
    let (status, _body) = run_handler("/verify/nonsense", async {
        Err(anyhow!("Verify route does not contain a payment hash"))
    })
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn verify_route_parses_the_payment_hash_not_the_route_prefix() {
    let payment_hash = sha256::Hash::hash(b"payment hash");

    let (parsed_hash, _query) = parse_verify_route(&format!("/verify/{payment_hash}"))
        .expect("the route is the verify route")
        .expect("the payment hash is the second path segment, not the first");

    assert_eq!(parsed_hash, payment_hash);
}

#[test]
fn verify_route_parses_the_wait_query_parameter() {
    let payment_hash = sha256::Hash::hash(b"payment hash");

    let (parsed_hash, query) = parse_verify_route(&format!("/verify/{payment_hash}?wait"))
        .expect("the route is the verify route")
        .expect("query parameters do not affect path parsing");

    assert_eq!(parsed_hash, payment_hash);
    assert!(query.contains_key("wait"));
}

#[test]
fn verify_route_with_a_malformed_payment_hash_is_rejected() {
    parse_verify_route("/verify/")
        .expect("the route is shaped like the verify route")
        .expect_err("a route with an empty payment hash has nothing to verify");
    parse_verify_route("/verify/not-a-payment-hash")
        .expect("the route is shaped like the verify route")
        .expect_err("a payment hash that is not a sha256 hash is rejected");
}

#[test]
fn only_the_exact_verify_route_reaches_the_verify_endpoint() {
    let payment_hash = sha256::Hash::hash(b"payment hash");

    // A route that is not exactly `/verify/{payment_hash}` is not this endpoint,
    // no matter that it starts with `/verify` or contains a valid payment hash
    // somewhere. Falling through to the handler lookup answers it with a 404,
    // like the HTTP path's exact route does.
    for route in [
        "/verify".to_string(),
        format!("/verifyfoo/{payment_hash}"),
        format!("/verify_something/{payment_hash}?wait"),
        format!("/verify/{payment_hash}/extra"),
        // Routes the URL parser normalizes are not the verify route either,
        // whether they normalize into it or out of it.
        format!("/../verify/{payment_hash}"),
        format!("/verify/{payment_hash}/../../stop"),
        "/verify/../stop".to_string(),
    ] {
        assert!(
            parse_verify_route(&route).is_none(),
            "{route} must not reach the unauthenticated verify handler"
        );
    }
}
