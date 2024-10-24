use std::fmt::Display;

use axum::response::{IntoResponse, Response};
use fedimint_core::config::{FederationId, FederationIdPrefix};
use fedimint_core::envs::is_env_var_set;
use fedimint_core::fmt_utils::OptStacktrace;
use reqwest::StatusCode;
use thiserror::Error;
use tracing::error;

use crate::envs::FM_DEBUG_GATEWAY_ENV;
use crate::lightning::LightningRpcError;
use crate::state_machine::pay::OutgoingPaymentError;

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
}

impl IntoResponse for PublicGatewayError {
    fn into_response(self) -> Response {
        // For privacy reasons, we do not return too many details about the failure of
        // the request back to the client to prevent malicious clients from
        // deducing state about the gateway/lightning node.
        error!("{self}");
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
        error!("{self}");
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
