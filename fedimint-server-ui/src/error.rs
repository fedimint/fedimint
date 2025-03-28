use axum::extract::FromRequest;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;
use tracing::debug;

use crate::LOG_UI;

/// Wrapper over `T` to make it a json request response
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(RequestError))]
pub struct AppJson<T>(pub T);

impl<T> IntoResponse for AppJson<T>
where
    axum::Json<T>: IntoResponse,
{
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

/// Whatever can go wrong with a request
#[derive(Debug, Error)]
pub enum RequestError {
    #[error("Bad request: {source}")]
    BadRequest { source: anyhow::Error },
    #[error("Internal Error")]
    InternalError,
}
pub type RequestResult<T> = std::result::Result<T, RequestError>;

impl IntoResponse for RequestError {
    fn into_response(self) -> Response {
        debug!(target: LOG_UI, err=%self, "Request Error");

        let (status_code, message) = match self {
            Self::BadRequest { source } => {
                (StatusCode::BAD_REQUEST, format!("Bad Request: {source}"))
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Service Error".to_owned(),
            ),
        };

        (status_code, AppJson(UserErrorResponse { message })).into_response()
    }
}

// How we want user errors responses to be serialized
#[derive(Serialize)]
pub struct UserErrorResponse {
    pub message: String,
}
