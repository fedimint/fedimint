use std::fmt::Display;

use axum::Json;
use axum::body::Body;
use axum::response::{IntoResponse, Response};
use fedimint_core::config::{FederationId, FederationIdPrefix};
use fedimint_core::crit;
use fedimint_core::envs::is_env_var_set;
use fedimint_core::fmt_utils::OptStacktrace;
use fedimint_gw_client::pay::OutgoingPaymentError;
use fedimint_lightning::LightningRpcError;
use fedimint_logging::LOG_GATEWAY;
use reqwest::StatusCode;
use thiserror::Error;

use crate::envs::FM_DEBUG_GATEWAY_ENV;

/// Top level error enum for all errors that can occur in the Gateway.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("Admin error: {0}")]
    Admin(#[from] AdminGatewayError),
    #[error("Public error: {0}")]
    Public(#[from] PublicGatewayError),
    #[error("{0}")]
    Lnurl(#[from] LnurlError),
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        match self {
            GatewayError::Admin(admin) => admin.into_response(),
            GatewayError::Public(public) => public.into_response(),
            GatewayError::Lnurl(lnurl) => lnurl.into_response(),
        }
    }
}

/// Errors that unauthenticated endpoints can encounter. For privacy reasons,
/// the error messages are intended to be redacted before returning to the
/// client.
#[derive(Debug, Error)]
pub enum PublicGatewayError {
    #[error("Lightning rpc error: {}", .0)]
    Lightning(#[from] LightningRpcError),
    #[error("LNv1 error: {:?}", .0)]
    LNv1(#[from] LNv1Error),
    #[error("LNv2 error: {:?}", .0)]
    LNv2(#[from] LNv2Error),
    #[error("{}", .0)]
    FederationNotConnected(#[from] FederationNotConnected),
    #[error("Failed to receive ecash: {failure_reason}")]
    ReceiveEcashError { failure_reason: String },
    #[error("Unexpected Error: {}", OptStacktrace(.0))]
    Unexpected(#[from] anyhow::Error),
}

impl IntoResponse for PublicGatewayError {
    fn into_response(self) -> Response {
        // For privacy reasons, we do not return too many details about the failure of
        // the request back to the client to prevent malicious clients from
        // deducing state about the gateway/lightning node.
        crit!(target: LOG_GATEWAY, "{self}");
        let (error_message, status_code) = match &self {
            PublicGatewayError::FederationNotConnected(e) => {
                (e.to_string(), StatusCode::BAD_REQUEST)
            }
            PublicGatewayError::ReceiveEcashError { .. } => (
                "Failed to receive ecash".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            PublicGatewayError::Lightning(_) => (
                "Lightning Network operation failed".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            PublicGatewayError::LNv1(_) => (
                "LNv1 operation failed, please contact gateway operator".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            PublicGatewayError::LNv2(_) => (
                "LNv2 operation failed, please contact gateway operator".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            PublicGatewayError::Unexpected(e) => (e.to_string(), StatusCode::BAD_REQUEST),
        };

        let error_message = if is_env_var_set(FM_DEBUG_GATEWAY_ENV) {
            self.to_string()
        } else {
            error_message
        };

        Response::builder()
            .status(status_code)
            .body(error_message.into())
            .expect("Failed to create Response")
    }
}

/// Errors that authenticated endpoints can encounter. Full error message and
/// error details are returned to the admin client for debugging purposes.
#[derive(Debug, Error)]
pub enum AdminGatewayError {
    #[error("Failed to create a federation client: {}", OptStacktrace(.0))]
    ClientCreationError(anyhow::Error),
    #[error("Failed to remove a federation client: {}", OptStacktrace(.0))]
    ClientRemovalError(String),
    #[error("There was an error with the Gateway's mnemonic: {}", OptStacktrace(.0))]
    MnemonicError(anyhow::Error),
    #[error("Unexpected Error: {}", OptStacktrace(.0))]
    Unexpected(#[from] anyhow::Error),
    #[error("{}", .0)]
    FederationNotConnected(#[from] FederationNotConnected),
    #[error("Error configuring the gateway: {}", OptStacktrace(.0))]
    GatewayConfigurationError(String),
    #[error("Lightning error: {}", OptStacktrace(.0))]
    Lightning(#[from] LightningRpcError),
    #[error("Error registering federation {federation_id}")]
    RegistrationError { federation_id: FederationId },
    #[error("Error withdrawing funds onchain: {failure_reason}")]
    WithdrawError { failure_reason: String },
}

impl IntoResponse for AdminGatewayError {
    // For admin errors, always pass along the full error message for debugging
    // purposes
    fn into_response(self) -> Response {
        crit!(target: LOG_GATEWAY, "{self}");
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(self.to_string().into())
            .expect("Failed to create Response")
    }
}

/// Errors that can occur during the LNv1 protocol. LNv1 errors are public and
/// the error messages should be redacted for privacy reasons.
#[derive(Debug, Error)]
pub enum LNv1Error {
    #[error("Incoming payment error: {}", OptStacktrace(.0))]
    IncomingPayment(String),
    #[error(
        "Outgoing Contract Error Reason: {message} Stack: {}",
        OptStacktrace(error)
    )]
    OutgoingContract {
        error: Box<OutgoingPaymentError>,
        message: String,
    },
    #[error("Outgoing Payment Error: {}", OptStacktrace(.0))]
    OutgoingPayment(#[from] anyhow::Error),
}

/// Errors that can occur during the LNv2 protocol. LNv2 errors are public and
/// the error messages should be redacted for privacy reasons.
#[derive(Debug, Error)]
pub enum LNv2Error {
    #[error("Incoming Payment Error: {}", .0)]
    IncomingPayment(String),
    #[error("Outgoing Payment Error: {}", OptStacktrace(.0))]
    OutgoingPayment(#[from] anyhow::Error),
}

/// Public error that indicates the requested federation is not connected to
/// this gateway.
#[derive(Debug, Error)]
pub struct FederationNotConnected {
    pub federation_id_prefix: FederationIdPrefix,
}

impl Display for FederationNotConnected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "No federation available for prefix {}",
            self.federation_id_prefix
        )
    }
}

/// LNURL-compliant error response for verify endpoints
#[derive(Debug, Error)]
pub(crate) struct LnurlError {
    code: StatusCode,
    reason: anyhow::Error,
}

impl Display for LnurlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LNURL Error: {}", self.reason,)
    }
}

impl LnurlError {
    pub(crate) fn internal(reason: anyhow::Error) -> Self {
        Self {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            reason,
        }
    }
}

impl IntoResponse for LnurlError {
    fn into_response(self) -> Response<Body> {
        let json = Json(serde_json::json!({
            "status": "ERROR",
            "reason": self.reason.to_string(),
        }));

        (self.code, json).into_response()
    }
}
