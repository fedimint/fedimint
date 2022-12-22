//! Implements the client API through which users interact with the federation
use std::fmt::Formatter;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use fedimint_api::server::ServerModule;
use fedimint_api::{
    config::ClientConfig,
    module::{api_endpoint, ApiEndpoint, ApiError},
    task::TaskHandle,
    TransactionId,
};
use fedimint_core::epoch::SerdeEpochHistory;
use fedimint_core::outcome::TransactionStatus;
use futures::FutureExt;
use jsonrpsee::{
    server::ServerBuilder,
    types::{error::CallError, ErrorObject},
    RpcModule,
};
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

    for module in fedimint.modules.modules() {
        attach_endpoints_erased(&mut rpc_module, module);
    }

    debug!(
        addr = cfg.local.api_bind_addr.to_string(),
        "Starting WSServer"
    );
    let server = ServerBuilder::new()
        .max_connections(cfg.local.max_connections)
        .ping_interval(Duration::from_secs(10))
        .build(&cfg.local.api_bind_addr.to_string())
        .await
        .context(format!("Bind address: {}", cfg.local.api_bind_addr))
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
    base_name: Option<&str>,
) {
    for endpoint in endpoints {
        let path = if let Some(base_name) = base_name {
            // This memory leak is fine because it only happens on server startup
            // and path has to live till the end of program anyways.
            Box::leak(format!("/{}{}", base_name, endpoint.path).into_boxed_str())
        } else {
            endpoint.path
        };

        // Another memory leak that is fine because the function is only called once at startup
        let handler: &'static _ = Box::leak(endpoint.handler);

        rpc_module
            .register_async_method(path, move |params, state| async move {
                let params = params.one::<serde_json::Value>()?;
                let fedimint = &state.fedimint;
                let mut dbtx = fedimint.database_transaction().await;
                dbtx.surpress_warning();
                // Using AssertUnwindSafe here is far from ideal. In theory this means we could
                // end up with an inconsistent state in theory. In practice most API functions
                // are only reading and the few that do write anything are atomic. Lastly, this
                // is only the last line of defense
                AssertUnwindSafe((handler)(fedimint, dbtx, params))
                    .catch_unwind()
                    .await
                    .map_err(|_| {
                        error!(path, "API handler panicked, DO NOT IGNORE, FIX IT!!!");
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
    server_module: &ServerModule,
) {
    let base_name = server_module.api_base_name();
    let endpoints = server_module.api_endpoints();
    let module_key = server_module.module_key();

    for endpoint in endpoints {
        // This memory leak is fine because it only happens on server startup
        // and path has to live till the end of program anyways.
        let path: &'static _ =
            Box::leak(format!("/{}{}", base_name, endpoint.path).into_boxed_str());
        let handler: &'static _ = Box::leak(endpoint.handler);

        rpc_module
            .register_async_method(path, move |params, state| async move {
                // Hack to avoid Sync/Send issues
                let params = params.one::<serde_json::Value>()?;
                let fedimint = &state.fedimint;
                let mut dbtx = fedimint.database_transaction().await;
                dbtx.surpress_warning();
                // Using AssertUnwindSafe here is far from ideal. In theory this means we could
                // end up with an inconsistent state in theory. In practice most API functions
                // are only reading and the few that do write anything are atomic. Lastly, this
                // is only the last line of defense
                AssertUnwindSafe((handler)(fedimint.modules.module(module_key), dbtx, params))
                    .catch_unwind()
                    .await
                    .map_err(|_| {
                        error!(path, "API handler panicked, DO NOT IGNORE, FIX IT!!!");
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
            async |fedimint: &FedimintConsensus, _dbtx, transaction: serde_json::Value| -> TransactionId {
                // deserializing Transaction from json Value always fails
                // we need to convert it to string first
                let string = serde_json::to_string(&transaction).map_err(|e| ApiError::bad_request(e.to_string()))?;
                let serde_transaction: SerdeTransaction = serde_json::from_str(&string).map_err(|e| ApiError::bad_request(e.to_string()))?;
                let transaction = serde_transaction.try_into_inner(&fedimint.modules.decoders()).map_err(|e| ApiError::bad_request(e.to_string()))?;

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
            "/epoch",
            async |fedimint: &FedimintConsensus, _dbtx, _v: ()| -> u64 {
                Ok(fedimint.get_last_epoch().await.ok_or_else(|| ApiError::not_found(String::from("epoch not found")))?)
            }
        },
        api_endpoint! {
            "/config",
            async |fedimint: &FedimintConsensus, _dbtx, _v: ()| -> ClientConfig {
                Ok(fedimint.cfg.consensus.to_client_config())
            }
        },
    ]
}
