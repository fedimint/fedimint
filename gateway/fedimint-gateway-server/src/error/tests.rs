use axum::body::to_bytes;
use axum::response::IntoResponse as _;
use reqwest::StatusCode;

use super::PublicGatewayError;

#[tokio::test]
async fn invariant_errors_return_a_sanitized_internal_error() {
    let error =
        PublicGatewayError::Internal(anyhow::anyhow!("configured module did not initialize"));
    assert_eq!(
        error.response_message("Gateway internal error".to_owned(), true),
        "Gateway internal error",
        "debug mode must not expose invariant details"
    );
    let response = error.into_response();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body reads"),
        "Gateway internal error"
    );
}
