use super::{GATEWAY_ERROR_RESPONSE_VERSION, GatewayErrorCode, GatewayErrorResponse};

#[test]
fn gateway_error_response_is_stable_and_versioned() {
    let response = GatewayErrorResponse::new(GatewayErrorCode::FederationUnreachable);

    assert_eq!(
        serde_json::to_value(response).expect("response serializes"),
        serde_json::json!({
            "version": GATEWAY_ERROR_RESPONSE_VERSION,
            "error": "federation_unreachable"
        })
    );
    assert_eq!(
        response.recognized_error(),
        Some(GatewayErrorCode::FederationUnreachable)
    );
}

#[test]
fn future_gateway_errors_fall_back_to_unrecognized() {
    let future_code: GatewayErrorResponse = serde_json::from_value(serde_json::json!({
        "version": GATEWAY_ERROR_RESPONSE_VERSION,
        "error": "future_failure"
    }))
    .expect("unknown error code remains decodable");
    let future_version = GatewayErrorResponse {
        version: GATEWAY_ERROR_RESPONSE_VERSION + 1,
        error: GatewayErrorCode::FederationUnreachable,
    };

    assert_eq!(future_code.error, GatewayErrorCode::Unknown);
    assert_eq!(future_code.recognized_error(), None);
    assert_eq!(future_version.recognized_error(), None);
}
