pub mod announcement;
mod http_auth;

use std::fmt::{self, Debug, Formatter};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use async_trait::async_trait;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased};
use fedimint_logging::LOG_NET_API;
use futures::FutureExt;
use jsonrpsee::server::{PingConfig, RpcServiceBuilder, ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObject;
use jsonrpsee::RpcModule;
use tracing::{error, info};

use crate::metrics;
use crate::net::api::http_auth::HttpAuthLayer;

#[derive(Clone, Encodable, Decodable, Default)]
pub struct ApiSecrets(Vec<String>);

impl fmt::Debug for ApiSecrets {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiSecrets")
            .field("num_secrets", &self.0.len())
            .finish()
    }
}

impl FromStr for ApiSecrets {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        if s.is_empty() {
            return Ok(Self(vec![]));
        }

        let secrets = s
            .split(',')
            .map(str::trim)
            .map(|s| {
                if s.is_empty() {
                    bail!("Empty Api Secret is not allowed")
                }
                Ok(s.to_string())
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(ApiSecrets(secrets))
    }
}

impl ApiSecrets {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get "active" secret - one that should be used to call other peers
    pub fn get_active(&self) -> Option<String> {
        self.0.first().cloned()
    }

    /// Get all secrets
    pub fn get_all(&self) -> &[String] {
        &self.0
    }

    /// Get empty value - meaning no secrets to use
    pub fn none() -> ApiSecrets {
        Self(vec![])
    }
}

/// A state that has context for the API, passed to each rpc handler callback
#[derive(Clone)]
pub struct RpcHandlerCtx<M> {
    pub rpc_context: Arc<M>,
}

impl<M> RpcHandlerCtx<M> {
    pub fn new_module(state: M) -> RpcModule<RpcHandlerCtx<M>> {
        RpcModule::new(Self {
            rpc_context: Arc::new(state),
        })
    }
}

impl<M: Debug> Debug for RpcHandlerCtx<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("State { ... }")
    }
}

/// How long to wait before timing out client connections
const API_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(60);

/// Has the context necessary for serving API endpoints
///
/// Returns the specific `State` the endpoint requires and the
/// `ApiEndpointContext` which all endpoints can access.
#[async_trait]
pub trait HasApiContext<State> {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&State, ApiEndpointContext<'_>);
}

/// A token proving the the API call was authenticated
///
/// Api handlers are encouraged to take it as an argument to avoid sensitive
/// guardian-only logic being accidentally unauthenticated.
pub struct GuardianAuthToken {
    _marker: (), // private field just to make creating it outside impossible
}

pub type ApiResult<T> = Result<T, ApiError>;

pub fn check_auth(context: &mut ApiEndpointContext) -> ApiResult<GuardianAuthToken> {
    if context.has_auth() {
        Ok(GuardianAuthToken { _marker: () })
    } else {
        Err(ApiError::unauthorized())
    }
}

pub async fn spawn<T>(
    name: &'static str,
    api_bind_addr: SocketAddr,
    module: RpcModule<RpcHandlerCtx<T>>,
    max_connections: u32,
    force_api_secrets: ApiSecrets,
) -> ServerHandle {
    info!(target: LOG_NET_API, "Starting api on ws://{api_bind_addr}");

    let builder =
        tower::ServiceBuilder::new().layer(HttpAuthLayer::new(force_api_secrets.get_all()));

    ServerBuilder::new()
        .max_connections(max_connections)
        .enable_ws_ping(PingConfig::new().ping_interval(Duration::from_secs(10)))
        .set_rpc_middleware(RpcServiceBuilder::new().layer(metrics::jsonrpsee::MetricsLayer))
        .set_http_middleware(builder)
        .build(&api_bind_addr.to_string())
        .await
        .context(format!("Bind address: {api_bind_addr}"))
        .context(format!("API name: {name}"))
        .expect("Could not build API server")
        .start(module)
}

pub fn attach_endpoints<State, T>(
    rpc_module: &mut RpcModule<RpcHandlerCtx<T>>,
    endpoints: Vec<ApiEndpoint<State>>,
    module_instance_id: Option<ModuleInstanceId>,
) where
    T: HasApiContext<State> + Sync + Send + 'static,
    State: Sync + Send + 'static,
{
    for endpoint in endpoints {
        let path = if let Some(module_instance_id) = module_instance_id {
            // This memory leak is fine because it only happens on server startup
            // and path has to live till the end of program anyways.
            Box::leak(format!("module_{}_{}", module_instance_id, endpoint.path).into_boxed_str())
        } else {
            endpoint.path
        };
        // Check if paths contain any abnormal characters
        assert!(
            !path.contains(|c: char| !matches!(c, '0'..='9' | 'a'..='z' | '_')),
            "Constructing bad path name {path}"
        );

        // Another memory leak that is fine because the function is only called once at
        // startup
        let handler: &'static _ = Box::leak(endpoint.handler);

        rpc_module
            .register_async_method(path, move |params, rpc_state, _extensions| async move {
                let params = params.one::<serde_json::Value>()?;
                let rpc_context = &rpc_state.rpc_context;

                // Using AssertUnwindSafe here is far from ideal. In theory this means we could
                // end up with an inconsistent state in theory. In practice most API functions
                // are only reading and the few that do write anything are atomic. Lastly, this
                // is only the last line of defense
                AssertUnwindSafe(tokio::time::timeout(API_ENDPOINT_TIMEOUT, async {
                    let request = serde_json::from_value(params)
                        .map_err(|e| ApiError::bad_request(e.to_string()))?;
                    let (state, context) = rpc_context.context(&request, module_instance_id).await;

                    (handler)(state, context, request).await
                }))
                .catch_unwind()
                .await
                .map_err(|_| {
                    error!(
                        target: LOG_NET_API,
                        path, "API handler panicked, DO NOT IGNORE, FIX IT!!!"
                    );
                    ErrorObject::owned(500, "API handler panicked", None::<()>)
                })?
                .map_err(|tokio::time::error::Elapsed { .. }| {
                    // TODO: find a better error for this, the error we used before:
                    // jsonrpsee::core::Error::RequestTimeout
                    // was moved to be client-side only
                    ErrorObject::owned(-32000, "Request timeout", None::<()>)
                })?
                .map_err(|e| ErrorObject::owned(e.code, e.message, None::<()>))
            })
            .expect("Failed to register async method");
    }
}
