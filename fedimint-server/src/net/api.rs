//! Implements the client API through which users interact with the federation
use std::fmt::Formatter;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use fedimint_core::config::ConfigResponse;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::epoch::SerdeEpochHistory;
use fedimint_core::module::{api_endpoint, ApiEndpoint, ApiError};
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

/// A state of fedimint server passed to each rpc handler callback
#[derive(Clone)]
pub struct RpcHandlerCtx {
    fedimint: Arc<FedimintConsensus>,
}

impl std::fmt::Debug for RpcHandlerCtx {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("State { ... }")
    }
}

pub async fn run_server(
    cfg: ServerConfig,
    fedimint: Arc<FedimintConsensus>,
    task_handle: TaskHandle,
) {
    let state = RpcHandlerCtx {
        fedimint: fedimint.clone(),
    };
    let mut rpc_module = RpcModule::new(state);

    attach_endpoints(&mut rpc_module, server_endpoints(), None);

    for (id, module) in fedimint.modules.iter_modules() {
        attach_endpoints_erased(&mut rpc_module, id, module);
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

// TODO: remove once modularized
fn attach_endpoints(
    rpc_module: &mut RpcModule<RpcHandlerCtx>,
    endpoints: Vec<ApiEndpoint<FedimintConsensus>>,
    module_instance_id: Option<ModuleInstanceId>,
) {
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
            .register_async_method(path, move |params, state| async move {
                let params = params.one::<serde_json::Value>()?;
                let fedimint = &state.fedimint;

                let dbtx = fedimint.db.begin_transaction().await;
                // Using AssertUnwindSafe here is far from ideal. In theory this means we could
                // end up with an inconsistent state in theory. In practice most API functions
                // are only reading and the few that do write anything are atomic. Lastly, this
                // is only the last line of defense
                AssertUnwindSafe((handler)(fedimint, dbtx, params, module_instance_id))
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
                    .map_err(|e| {
                        jsonrpsee::core::Error::Call(CallError::Custom(ErrorObject::owned(
                            e.code, e.message, None::<()>,
                        )))
                    })
            })
            .expect("Failed to register async method");
    }
}

fn attach_endpoints_erased(
    rpc_module: &mut RpcModule<RpcHandlerCtx>,
    module_instance: ModuleInstanceId,
    server_module: &DynServerModule,
) {
    let endpoints = server_module.api_endpoints();

    for endpoint in endpoints {
        // This memory leak is fine because it only happens on server startup
        // and path has to live till the end of program anyways.
        let path: &'static _ =
            Box::leak(format!("/module/{}{}", module_instance, endpoint.path).into_boxed_str());
        let handler: &'static _ = Box::leak(endpoint.handler);

        rpc_module
            .register_async_method(path, move |params, state| async move {
                // Hack to avoid Sync/Send issues
                let params = params.one::<serde_json::Value>()?;
                let fedimint = &state.fedimint;
                let dbtx = fedimint.db.begin_transaction().await;
                // Using AssertUnwindSafe here is far from ideal. In theory this means we could
                // end up with an inconsistent state in theory. In practice most API functions
                // are only reading and the few that do write anything are atomic. Lastly, this
                // is only the last line of defense
                AssertUnwindSafe((handler)(
                    fedimint.modules.get_expect(module_instance),
                    dbtx,
                    params,
                    Some(module_instance),
                ))
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
            async |fedimint: &FedimintConsensus, _dbtx, serde_transaction: SerdeTransaction| -> TransactionId {
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
            async |fedimint: &FedimintConsensus, _dbtx, tx_hash: TransactionId| -> TransactionStatus {
                debug!(transaction = %tx_hash, "Recieved request");

                let tx_status = fedimint.transaction_status(tx_hash).await.ok_or_else(|| ApiError::not_found(String::from("transaction not found")))?;

                debug!(transaction = %tx_hash, "Sending outcome");
                Ok(tx_status)
            }
        },
        api_endpoint! {
            "/fetch_epoch_history",
            async |fedimint: &FedimintConsensus, _dbtx, epoch: u64| -> SerdeEpochHistory {
                let epoch = fedimint.epoch_history(epoch).await.ok_or_else(|| ApiError::not_found(String::from("epoch not found")))?;
                Ok((&epoch).into())
            }
        },
        api_endpoint! {
            "/fetch_epoch_count",
            async |fedimint: &FedimintConsensus, _dbtx, _v: ()| -> u64 {
                Ok(fedimint.get_epoch_count().await)
            }
        },
        api_endpoint! {
            "/config",
            async |fedimint: &FedimintConsensus, dbtx, _v: ()| -> ConfigResponse {
                Ok(fedimint.get_config_with_sig(dbtx).await)
            }
        },
    ]
}
