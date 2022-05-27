use crate::clients::user::ClientError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug)]
pub enum Error {
    /// Request error
    Request(reqwest::Error),
    /// Error response
    Rpc(RpcError),
    /// Wrong result
    ResultMissmatch,
}

#[derive(Debug)]
pub enum StandardError {
    /// Invalid JSON was received by the server.
    /// An error occurred on the server while parsing the JSON text.
    ParseError,
    /// The JSON sent is not a valid Request object.
    InvalidRequest,
    /// The method does not exist / is not available.
    MethodNotFound,
    /// Invalid method parameter(s).
    InvalidParams,
    /// Internal JSON-RPC error.
    InternalError,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// A JSONRPC error object
pub struct RpcError {
    /// The integer identifier of the error
    pub code: i32,
    /// A string describing the error
    pub message: String, //TODO: look into String vs &str I think I can use &str here which would be better
    /// Additional data specific to the error
    pub data: Option<Value>,
}

impl From<ClientError> for RpcError {
    fn from(e: ClientError) -> Self {
        standard_error(
            StandardError::InternalError,
            Some(serde_json::Value::String(format!("{:?}", e))),
        )
    }
}

/// Create a standard error responses
pub fn standard_error(code: StandardError, data: Option<Value>) -> RpcError {
    match code {
        StandardError::ParseError => RpcError {
            code: -32700,
            message: "Parse error".to_string(),
            data,
        },
        StandardError::InvalidRequest => RpcError {
            code: -32600,
            message: "Invalid Request".to_string(),
            data,
        },
        StandardError::MethodNotFound => RpcError {
            code: -32601,
            message: "Method not found".to_string(),
            data,
        },
        StandardError::InvalidParams => RpcError {
            code: -32602,
            message: "Invalid params".to_string(),
            data,
        },
        StandardError::InternalError => RpcError {
            code: -32603,
            message: "Internal error".to_string(),
            data,
        },
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Self::Request(e)
    }
}
