/*
Copyright (C) 2007-2010 by the JSON-RPC Working Group

This document and translations of it may be used to implement JSON-RPC, it may be copied and furnished to others, and derivative works that comment on or otherwise explain it or assist in its implementation may be prepared, copied, published and distributed, in whole or in part, without restriction of any kind, provided that the above copyright notice and this paragraph are included on all such copies and derivative works. However, this document itself may not bemodified in any way.

The limited permissions granted above are perpetual and will not be revoked.

This document and the information contained herein is provided "AS IS" and ALL WARRANTIES, EXPRESS OR IMPLIED are DISCLAIMED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 */
use crate::clients::user::{ClientError, EventLog};
use crate::{LightningGateway, UserClient};
use futures::future::BoxFuture;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

pub const JSON_RPC: &str = "2.0";
///JSON-RPC Request object
#[derive(Deserialize)]
pub struct Request {
    ///A String specifying the version of the JSON-RPC protocol. MUST be exactly "2.0".
    ///If it's none demand a jsonrpc 2.0 spec. request
    pub jsonrpc: Option<String>,
    ///A String containing the name of the method to be invoked.
    ///Method names that begin with the word rpc followed by a period character (U+002E or ASCII 46) are reserved for rpc-internal methods
    ///and extensions and MUST NOT be used for anything else.
    pub method: String,
    ///A Structured value that holds the parameter values to be used during the invocation of the method. This member MAY be omitted.
    pub params: Value,
    ///An identifier established by the Client that MUST contain a String, Number, or NULL value if included.
    ///If it is not included it is assumed to be a notification. The value SHOULD normally not be Null and Numbers SHOULD NOT contain fractional parts
    pub id: Option<Value>,
}
///JSON-RPC Response object
#[derive(Serialize)]
pub struct Response<'a> {
    ///A String specifying the version of the JSON-RPC protocol. MUST be exactly "2.0".
    pub jsonrpc: &'a str,
    ///This member is REQUIRED on success.
    ///This member MUST NOT exist if there was an error invoking the method.
    ///The value of this member is determined by the method invoked on the Server.
    pub result: Option<Value>,
    ///This member is REQUIRED on error.
    ///This member MUST NOT exist if there was no error triggered during invocation.
    ///The value for this member MUST be an Object as defined in section 5.1.
    pub error: Option<RpcError>,
    ///This member is REQUIRED.
    ///It MUST be the same as the value of the id member in the Request Object.
    ///If there was an error in detecting the id in the Request object (e.g. Parse error/Invalid Request), it MUST be Null.
    pub id: Option<Value>,
}
impl Response<'_> {
    pub fn with_result(result: Value, id: Value) -> Self {
        Response {
            jsonrpc: JSON_RPC,
            result: Some(result),
            error: None,
            id: Some(id),
        }
    }
    pub fn with_error(error: RpcError, id: Option<Value>) -> Self {
        Response {
            jsonrpc: JSON_RPC,
            result: None,
            error: Some(error),
            id,
        }
    }
}

//I copied all error stuff from https://github.com/apoelstra/rust-jsonrpc/blob/master/src/error.rs
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

///RPC-API Endpoint-Router
pub struct Shared {
    pub client: Arc<UserClient>,
    pub gateway: Arc<LightningGateway>,
    pub rng: OsRng,
    pub router: Arc<Router>,
    pub events: Arc<EventLog>,
    pub spend_lock: Arc<Mutex<()>>,
}

type HandlerArgs = Value;
type Share = Arc<Shared>;
type HandlerResult = Result<Value, RpcError>;

pub struct Handler {
    func: Box<
        dyn Fn(HandlerArgs, Share) -> BoxFuture<'static, HandlerResult> + Send + Sync + 'static,
    >,
}

impl Handler {
    pub fn new<P>(raw_func: fn(params: Value, shared: Share) -> P) -> Handler
    where
        P: Future<Output = HandlerResult> + Send + 'static,
    {
        Handler {
            func: Box::new(move |params, shared| Box::pin(raw_func(params, shared))),
        }
    }

    pub async fn call(&self, args: HandlerArgs, shared: Share) -> HandlerResult {
        (self.func)(args, shared).await
    }
}

pub struct Router {
    handlers: HashMap<String, Handler>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }
    pub fn add_handler<P>(mut self, name: &str, fun: fn(Value, Share) -> P) -> Self
    where
        P: Future<Output = HandlerResult> + Send + 'static,
    {
        self.handlers.insert(name.to_string(), Handler::new(fun));
        self
    }
    pub fn get(&self, name: &str) -> Option<&Handler> {
        self.handlers.get(name)
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}
