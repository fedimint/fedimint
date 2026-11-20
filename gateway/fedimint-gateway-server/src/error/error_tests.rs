use axum::body::to_bytes;
use fedimint_core::module::{
    GATEWAY_ERROR_RESPONSE_VERSION, GatewayErrorCode, GatewayErrorResponse,
};

use super::PublicGatewayError;

#[tokio::test]
async fn federation_unreachable_response_is_sanitized() {
    let response = PublicGatewayError::FederationUnreachable.into_response_with_debug(true);
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body can be read");
    let body: serde_json::Value =
        serde_json::from_slice(&body).expect("response uses structured JSON");
    let parsed: GatewayErrorResponse =
        serde_json::from_value(body.clone()).expect("response uses the versioned envelope");

    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(parsed.version, GATEWAY_ERROR_RESPONSE_VERSION);
    assert_eq!(parsed.error, GatewayErrorCode::FederationUnreachable);
    assert_eq!(
        body,
        serde_json::json!({
            "version": GATEWAY_ERROR_RESPONSE_VERSION,
            "error": "federation_unreachable"
        })
    );
    assert!(!body.to_string().contains("sensitive-debug-sentinel"));
}
