use anyhow::anyhow;
use fedimint_api_client::api::ServerError;
use fedimint_core::module::{
    GATEWAY_ERROR_RESPONSE_VERSION, GatewayErrorCode, GatewayErrorResponse,
};

use super::pay::GatewayPayError;

#[test]
fn recognized_gateway_error_maps_to_stable_failure() {
    let error = ServerError::GatewayResponse {
        status: 503,
        response: GatewayErrorResponse::new(GatewayErrorCode::FederationUnreachable),
    };

    assert_eq!(
        GatewayPayError::from_server_error(error),
        GatewayPayError::FederationUnreachable
    );
}

#[test]
fn legacy_and_future_gateway_errors_keep_generic_fallback() {
    let legacy =
        GatewayPayError::from_server_error(ServerError::InvalidRequest(anyhow!("legacy response")));
    let future = GatewayPayError::from_server_error(ServerError::GatewayResponse {
        status: 503,
        response: GatewayErrorResponse {
            version: GATEWAY_ERROR_RESPONSE_VERSION + 1,
            error: GatewayErrorCode::FederationUnreachable,
        },
    });

    assert!(matches!(
        legacy,
        GatewayPayError::GatewayInternalError { .. }
    ));
    assert!(matches!(
        future,
        GatewayPayError::GatewayInternalError { .. }
    ));
}
