//! Implements the client API through which users interact with the federation
use std::fmt::{Debug, Formatter};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use fedimint_core::config::ConfigResponse;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::epoch::SerdeEpochHistory;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased,
};
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskHandle;
use fedimint_core::TransactionId;
use fedimint_logging::LOG_NET_API;
use futures::FutureExt;
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::types::error::CallError;
use jsonrpsee::types::ErrorObject;
use jsonrpsee::RpcModule;
use tracing::{debug, error};

use crate::config::ServerConfig;
use crate::consensus::FedimintConsensus;
use crate::transaction::SerdeTransaction;

/// A state that has context for the API, passed to each rpc handler callback
#[derive(Clone)]
pub struct RpcHandlerCtx<M> {
    pub rpc_context: Arc<M>,
}

impl<M: Debug> Debug for RpcHandlerCtx<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("State { ... }")
    }
}

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

#[async_trait]
impl HasApiContext<FedimintConsensus> for FedimintConsensus {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&FedimintConsensus, ApiEndpointContext<'_>) {
        (
            self,
            ApiEndpointContext::new(
                request.auth == Some(self.cfg.private.api_auth.clone()),
                self.db.begin_transaction().await,
                id,
            ),
        )
    }
}

#[async_trait]
impl HasApiContext<DynServerModule> for FedimintConsensus {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&DynServerModule, ApiEndpointContext<'_>) {
        let (_, context): (&FedimintConsensus, _) = self.context(request, id).await;
        (
            self.modules.get_expect(id.expect("required module id")),
            context,
        )
    }
}

pub async fn run_server(
    cfg: ServerConfig,
    fedimint: Arc<FedimintConsensus>,
    task_handle: TaskHandle,
) {
    let state = RpcHandlerCtx {
        rpc_context: fedimint.clone(),
    };
    let mut rpc_module = RpcModule::new(state);

    attach_endpoints(&mut rpc_module, server_endpoints(), None);

    for (id, module) in fedimint.modules.iter_modules() {
        attach_endpoints(&mut rpc_module, module.api_endpoints(), Some(id));
    }

    debug!(addr = cfg.local.api_bind.to_string(), "Starting WSServer");
    let server = ServerBuilder::new()
        .max_connections(cfg.local.max_connections)
        .ping_interval(Duration::from_secs(10))
        .build(&cfg.local.api_bind.to_string())
        .await
        .context(format!("Bind address: {}", cfg.local.api_bind))
        .expect("Could not start API server");

    let server_handle = server
        .start(rpc_module)
        .expect("Could not start API server");

    let stop_handle = server_handle.clone();

    task_handle
        .on_shutdown(Box::new(move || {
            Box::pin(async move {
                // ignore errors: we don't care if already stopped
                let _ = stop_handle.stop();
            })
        }))
        .await;

    server_handle.stopped().await
}

const API_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(60);

/// Attaches `endpoints` to the `RpcModule`
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
            Box::leak(format!("/module/{}{}", module_instance_id, endpoint.path).into_boxed_str())
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
                    let (state, context) = rpc_context.context(&request, module_instance_id).await;

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

fn server_endpoints() -> Vec<ApiEndpoint<FedimintConsensus>> {
    vec![
        api_endpoint! {
            "/transaction",
            async |fedimint: &FedimintConsensus, _context, serde_transaction: SerdeTransaction| -> TransactionId {
                let transaction = serde_transaction.try_into_inner(&fedimint.modules.decoder_registry()).map_err(|e| ApiError::bad_request(e.to_string()))?;

                let tx_id = transaction.tx_hash();

                fedimint.submit_transaction(transaction)
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;

                Ok(tx_id)
            }
        },
        api_endpoint! {
            "/fetch_transaction",
            async |fedimint: &FedimintConsensus, _context, tx_hash: TransactionId| -> Option<TransactionStatus> {
                debug!(transaction = %tx_hash, "Received request");

                let tx_status = fedimint.transaction_status(tx_hash)
                    .await;

                debug!(transaction = %tx_hash, "Sending outcome");
                Ok(tx_status)
            }
        },
        api_endpoint! {
            "/wait_transaction",
            async |fedimint: &FedimintConsensus, _context, tx_hash: TransactionId| -> TransactionStatus {
                debug!(transaction = %tx_hash, "Received request");

                let tx_status = fedimint.wait_transaction_status(tx_hash)
                    .await;

                debug!(transaction = %tx_hash, "Sending outcome");
                Ok(tx_status)
            }
        },
        api_endpoint! {
            "/fetch_epoch_history",
            async |fedimint: &FedimintConsensus, _context, epoch: u64| -> SerdeEpochHistory {
                let epoch = fedimint.epoch_history(epoch).await.ok_or_else(|| ApiError::not_found(String::from("epoch not found")))?;
                Ok((&epoch).into())
            }
        },
        api_endpoint! {
            "/fetch_epoch_count",
            async |fedimint: &FedimintConsensus, _context, _v: ()| -> u64 {
                Ok(fedimint.get_epoch_count().await)
            }
        },
        api_endpoint! {
            "/config",
            async |fedimint: &FedimintConsensus, context, _v: ()| -> ConfigResponse {
                Ok(fedimint.get_config_with_sig(&mut context.dbtx()).await)
            }
        },
        api_endpoint! {
            "upgrade",
            async |fedimint: &FedimintConsensus, context, _v: ()| -> () {
                if context.has_auth() {
                    fedimint.signal_upgrade().await.map_err(|_| ApiError::server_error("Unable to send signal to server".to_string()))?;
                    Ok(())
                } else {
                    Err(ApiError::unauthorized())
                }
            }
        },
    ]
}
