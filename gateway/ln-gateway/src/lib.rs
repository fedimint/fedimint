pub mod client;
pub mod cln;
pub mod config;
pub mod gatewayd;
pub mod ln;
pub mod rpc;
pub mod utils;

pub mod gatewaylnrpc {
    tonic::include_proto!("gatewaylnrpc");
}

use std::borrow::Cow;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use mint_client::mint::MintClientError;
use mint_client::ClientError;
use thiserror::Error;
use tracing::error;

use crate::ln::LightningError;
use crate::rpc::ReceivePaymentPayload;

pub type Result<T> = std::result::Result<T, LnGatewayError>;

#[derive(Debug, Error)]
pub enum LnGatewayError {
    #[error("Federation client operation error: {0:?}")]
    ClientError(#[from] ClientError),
    #[error("Lightning rpc operation error: {0:?}")]
    LnRpcError(#[from] tonic::Status),
    #[error("Our LN node could not route the payment: {0:?}")]
    CouldNotRoute(LightningError),
    #[error("Mint client error: {0:?}")]
    MintClientE(#[from] MintClientError),
    #[error("Actor not found")]
    UnknownFederation,
    #[error("Other: {0:?}")]
    Other(#[from] anyhow::Error),
}

impl IntoResponse for LnGatewayError {
    fn into_response(self) -> Response {
        let mut err = Cow::<'static, str>::Owned(format!("{self:?}")).into_response();
        *err.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        err
    }
}
