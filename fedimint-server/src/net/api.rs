//! Implements the client API through which users interact with the federation
use std::fmt::Formatter;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use fedimint_api::{
    config::GenerateConfig,
    module::{api_endpoint, ApiEndpoint, ApiError},
    FederationModule, TransactionId,
};
use fedimint_core::config::ClientConfig;
use fedimint_core::epoch::EpochHistory;
use fedimint_core::outcome::TransactionStatus;
use futures::future::BoxFuture;
use futures::FutureExt;
use jsonrpsee::{
    types::{error::CallError, ErrorObject},
    ws_server::WsServerBuilder,
    RpcModule,
};
use tracing::{debug, error};

use crate::config::ServerConfig;
use crate::consensus::FedimintConsensus;
use crate::transaction::Transaction;

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

impl fedimint_core_api::server::RpcHandlerCtx for FedimintConsensus {}

struct InitHandle<'a> {
    rpc_module: &'a mut RpcModule<RpcHandlerCtx>,
}

impl<'a> fedimint_core_api::server::InitHandle for InitHandle<'a> {
    fn register_endpoint(
        &mut self,
        path: &'static str,
        handler: fn(
            serde_json::Value,
            &dyn fedimint_core_api::server::RpcHandlerCtx,
        ) -> BoxFuture<'static, Result<serde_json::Value, ApiError>>,
    ) {
        self.rpc_module
            .register_async_method(path, move |params, state| {
                Box::pin(async move {
                    let params = params.one::<serde_json::Value>()?;
                    // Using AssertUnwindSafe here is far from ideal. In theory this means we could
                    // end up with an inconsistent state in theory. In practice most API functions
                    // are only reading and the few that do write anything are atomic. Lastly, this
                    // is only the last line of defense
                    AssertUnwindSafe(handler(params, &*state.fedimint))
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
            })
            .expect("Failed to register async method");
    }
}

pub async fn run_server(cfg: ServerConfig, fedimint: Arc<FedimintConsensus>) {
    let state = RpcHandlerCtx {
        fedimint: fedimint.clone(),
    };
    let mut rpc_module = RpcModule::new(state);

    attach_endpoints(&mut rpc_module, server_endpoints(), None);
    attach_endpoints(
        &mut rpc_module,
        fedimint.wallet.api_endpoints(),
        Some(fedimint.wallet.api_base_name()),
    );

    for module in fedimint.modules.values() {
        module.init(&mut InitHandle {
            rpc_module: &mut rpc_module,
        });
    }

    attach_endpoints(
        &mut rpc_module,
        fedimint.ln.api_endpoints(),
        Some(fedimint.ln.api_base_name()),
    );

    let server = WsServerBuilder::new()
        .build(&cfg.api_bind_addr)
        .await
        .expect("Could not start API server");

    server
        .start(rpc_module)
        .expect("Could not start API server")
        .await;
}

fn attach_endpoints<M>(
    rpc_module: &mut RpcModule<RpcHandlerCtx>,
    endpoints: &'static [ApiEndpoint<M>],
    base_name: Option<&str>,
) where
    FedimintConsensus: AsRef<M>,
    M: Sync,
{
    for endpoint in endpoints {
        let endpoint: &'static ApiEndpoint<M> = endpoint;
        let path = if let Some(base_name) = base_name {
            // This memory leak is fine because it only happens on server startup
            // and path has to live till the end of program anyways.
            Box::leak(format!("/{}{}", base_name, endpoint.path).into_boxed_str())
        } else {
            endpoint.path
        };
        rpc_module
            .register_async_method(path, move |params, state| {
                Box::pin(async move {
                    let params = params.one::<serde_json::Value>()?;
                    // Using AssertUnwindSafe here is far from ideal. In theory this means we could
                    // end up with an inconsistent state in theory. In practice most API functions
                    // are only reading and the few that do write anything are atomic. Lastly, this
                    // is only the last line of defense
                    AssertUnwindSafe((endpoint.handler)((*state.fedimint).as_ref(), params))
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
            })
            .expect("Failed to register async method");
    }
}

fn server_endpoints() -> &'static [ApiEndpoint<FedimintConsensus>] {
    const ENDPOINTS: &[ApiEndpoint<FedimintConsensus>] = &[
        api_endpoint! {
            "/transaction",
            async |fedimint: &FedimintConsensus, transaction: serde_json::Value| -> TransactionId {
                // deserializing Transaction from json Value always fails
                // we need to convert it to string first
                let string = serde_json::to_string(&transaction).map_err(|e| ApiError::bad_request(e.to_string()))?;
                let transaction: Transaction = serde_json::from_str(&string).map_err(|e| ApiError::bad_request(e.to_string()))?;
                let tx_id = transaction.tx_hash();

                fedimint
                    .submit_transaction(transaction)
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;

                Ok(tx_id)
            }
        },
        api_endpoint! {
            "/fetch_transaction",
            async |fedimint: &FedimintConsensus, tx_hash: TransactionId| -> TransactionStatus {
                debug!(transaction = %tx_hash, "Recieved request");

                let tx_status = fedimint.transaction_status(tx_hash).ok_or_else(|| ApiError::not_found(String::from("transaction not found")))?;

                debug!(transaction = %tx_hash, "Sending outcome");
                Ok(tx_status)
            }
        },
        api_endpoint! {
            "/fetch_epoch_history",
            async |fedimint: &FedimintConsensus, epoch: u64| -> EpochHistory {
                let epoch = fedimint.epoch_history(epoch).ok_or_else(|| ApiError::not_found(String::from("epoch not found")))?;
                Ok(epoch)
            }
        },
        api_endpoint! {
            "/config",
            async |fedimint: &FedimintConsensus, _v: ()| -> ClientConfig {
                Ok(fedimint.cfg.to_client_config())
            }
        },
    ];

    ENDPOINTS
}
