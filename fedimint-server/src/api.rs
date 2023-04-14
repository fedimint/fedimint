use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::Database;
use fedimint_core::module::{ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased};
use fedimint_core::task::{TaskGroup, TaskHandle};
use fedimint_logging::LOG_NET_API;
use futures::FutureExt;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::types::error::CallError;
use jsonrpsee::types::ErrorObject;
use jsonrpsee::RpcModule;
use tracing::{debug, error};
use fedimint_logging::LOG_TASK;
use crate::config::api::{ConfigGenApi, ConfigGenSettings};
use crate::config::io::read_server_config;
use crate::config::ServerConfig;
use crate::net::api::{ConsensusApi, RpcHandlerCtx};
use crate::{config, net, FedimintServer};

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

pub struct FedimintApi;

impl FedimintApi {
    /// Starts the config gen API
    ///
    /// Runs the consensus server once the configuration has been created
    /// If the server exits, restarts config gen
    // TODO: combine with net::run_server and replace DKG CLI with the API
    pub async fn run_config_gen(
        data_dir: PathBuf,
        settings: ConfigGenSettings,
        db: Database,
        mut task_group: TaskGroup,
    ) -> anyhow::Result<()> {
        loop {
            let (config_generated_tx, mut config_generated_rx) = tokio::sync::mpsc::channel(1);
            let state = RpcHandlerCtx {
                rpc_context: Arc::new(ConfigGenApi::new(
                    data_dir.clone(),
                    settings.clone(),
                    db.clone(),
                    config_generated_tx,
                )),
            };
            let mut rpc_module = RpcModule::new(state);

            Self::attach_endpoints(&mut rpc_module, config::api::server_endpoints(), None);

            let server_handle =
                Self::start_server(rpc_module, settings.api_bind, task_group.make_handle(), 10)
                    .await;

            // TODO: Return failures by restarting the config API
            let auth = config_generated_rx.recv().await.expect("should not close");
            server_handle.stop().expect("Able to stop server");
            let cfg = read_server_config(&auth.0, data_dir.clone())?;
            FedimintServer::run(
                cfg,
                db.clone(),
                settings.registry.clone(),
                None,
                &mut task_group,
            )
            .await?;
        }
    }

    /// Starts the consensus API
    pub async fn run_consensus(
        cfg: ServerConfig,
        fedimint: Arc<ConsensusApi>,
        task_handle: TaskHandle,
    ) {
        let state = RpcHandlerCtx {
            rpc_context: fedimint.clone(),
        };
        let mut rpc_module = RpcModule::new(state);

        Self::attach_endpoints(&mut rpc_module, net::api::server_endpoints(), None);

        for (id, module) in fedimint.modules.iter_modules() {
            Self::attach_endpoints(&mut rpc_module, module.api_endpoints(), Some(id));
        }

        let server_handle = Self::start_server(
            rpc_module,
            cfg.local.api_bind,
            task_handle,
            cfg.local.max_connections,
        )
        .await;

        server_handle.stopped().await
    }

    async fn start_server<T>(
        module: RpcModule<RpcHandlerCtx<T>>,
        bind: SocketAddr,
        task_handle: TaskHandle,
        max_connections: u32,
    ) -> ServerHandle {
        let server_handle = ServerBuilder::new()
            .max_connections(max_connections)
            .ping_interval(Duration::from_secs(10))
            .build(&bind.to_string())
            .await
            .context(format!("Bind address: {bind}"))
            .expect("Could not start API server")
            .start(module)
            .expect("Could not start API server");

        let stop_handle = server_handle.clone();

        task_handle
            .on_shutdown(Box::new(move || {
                Box::pin(async move {
                    debug!(target: LOG_TASK, "Shutting down jsonrpcsee server");
                    // ignore errors: we don't care if already stopped
                    let _ = stop_handle.stop();
                })
            }))
            .await;

        server_handle
    }

    /// Attaches `endpoints` to the `RpcModule`
    fn attach_endpoints<State, T>(
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
                Box::leak(
                    format!("/module/{}{}", module_instance_id, endpoint.path).into_boxed_str(),
                )
            } else {
                endpoint.path
            };

            // Another memory leak that is fine because the function is only called once at
            // startup
            let handler: &'static _ = Box::leak(endpoint.handler);

            rpc_module
                .register_async_method(path, move |params, rpc_state| async move {
                    let params = params.one::<serde_json::Value>()?;
                    let rpc_context = &rpc_state.rpc_context;

                    // Using AssertUnwindSafe here is far from ideal. In theory this means we could
                    // end up with an inconsistent state in theory. In practice most API functions
                    // are only reading and the few that do write anything are atomic. Lastly, this
                    // is only the last line of defense
                    AssertUnwindSafe(tokio::time::timeout(API_ENDPOINT_TIMEOUT, async {
                        let request = serde_json::from_value(params)
                            .map_err(|e| ApiError::bad_request(e.to_string()))?;
                        let (state, context) =
                            rpc_context.context(&request, module_instance_id).await;

                        let res = (handler)(state, context, request).await;

                        res
                    }))
                    .catch_unwind()
                    .await
                    .map_err(|_| {
                        error!(
                            target: LOG_NET_API,
                            path, "API handler panicked, DO NOT IGNORE, FIX IT!!!"
                        );
                        jsonrpsee::core::Error::Call(CallError::Custom(ErrorObject::owned(
                            500,
                            "API handler panicked",
                            None::<()>,
                        )))
                    })?
                    .map_err(|tokio::time::error::Elapsed { .. }| {
                        jsonrpsee::core::Error::RequestTimeout
                    })?
                    .map_err(|e| {
                        jsonrpsee::core::Error::Call(CallError::Custom(ErrorObject::owned(
                            e.code, e.message, None::<()>,
                        )))
                    })
                })
                .expect("Failed to register async method");
        }
    }
}
