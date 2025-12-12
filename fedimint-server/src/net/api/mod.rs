pub mod announcement;
pub mod guardian_metadata;
mod http_auth;

use std::fmt::{self, Formatter};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased};
use fedimint_logging::LOG_NET_API;
use futures::FutureExt;
use jsonrpsee::RpcModule;
use jsonrpsee::server::{PingConfig, RpcServiceBuilder, ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObject;
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
    ) -> (&State, ApiEndpointContext);
}

pub async fn spawn<T>(
    name: &'static str,
    api_bind: SocketAddr,
    module: RpcModule<T>,
    max_connections: u32,
    api_secrets: ApiSecrets,
) -> ServerHandle {
    info!(target: LOG_NET_API, "Starting http api on ws://{api_bind}");

    let builder = tower::ServiceBuilder::new().layer(HttpAuthLayer::new(api_secrets.get_all()));

    ServerBuilder::new()
        .max_connections(max_connections)
        .enable_ws_ping(PingConfig::new().ping_interval(Duration::from_secs(10)))
        .set_rpc_middleware(RpcServiceBuilder::new().layer(metrics::jsonrpsee::MetricsLayer))
        .set_http_middleware(builder)
        .build(&api_bind.to_string())
        .await
        .context(format!("Bind address: {api_bind}"))
        .context(format!("API name: {name}"))
        .expect("Could not build API server")
        .start(module)
}

pub fn attach_endpoints<State, T>(
    rpc_module: &mut RpcModule<T>,
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

                // Using AssertUnwindSafe here is far from ideal. In theory this means we could
                // end up with an inconsistent state in theory. In practice most API functions
                // are only reading and the few that do write anything are atomic. Lastly, this
                // is only the last line of defense
                AssertUnwindSafe(tokio::time::timeout(API_ENDPOINT_TIMEOUT, async {
                    let request = serde_json::from_value(params)
                        .map_err(|e| ApiError::bad_request(e.to_string()))?;

                    let (state, context) = rpc_state.context(&request, module_instance_id).await;

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
