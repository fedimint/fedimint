//! Implements the client API through which users interact with the federation
use std::fmt::{Debug, Formatter};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_core::api::WsClientConnectInfo;
use fedimint_core::config::ConfigResponse;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction, ModuleDatabaseTransaction};
use fedimint_core::epoch::{SerdeEpochHistory, SerdeSignature, SignedEpochOutcome};
use fedimint_core::module::registry::ServerModuleRegistry;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased,
};
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskHandle;
use fedimint_core::transaction::Transaction;
use fedimint_core::{OutPoint, TransactionId};
use fedimint_logging::LOG_NET_API;
use futures::FutureExt;
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::types::error::CallError;
use jsonrpsee::types::ErrorObject;
use jsonrpsee::RpcModule;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error};

use crate::config::api::ApiResult;
use crate::config::ServerConfig;
use crate::consensus::interconnect::FedimintInterconnect;
use crate::consensus::TransactionSubmissionError::TransactionReplayError;
use crate::consensus::{
    AcceptedTransaction, ApiEvent, FundingVerifier, TransactionSubmissionError,
};
use crate::db::{
    AcceptedTransactionKey, ClientConfigDownloadKey, ClientConfigSignatureKey, EpochHistoryKey,
    LastEpochKey, RejectedTransactionKey,
};
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

#[derive(Clone)]
pub struct ConsensusApi {
    /// Our server configuration
    pub cfg: ServerConfig,
    /// Database for serving the API
    pub db: Database,
    /// Modules registered with the federation
    pub modules: ServerModuleRegistry,
    /// Cached client config response
    pub client_cfg: ConfigResponse,
    /// For sending API events to consensus such as transactions
    pub api_sender: Sender<ApiEvent>,
}

impl ConsensusApi {
    pub async fn submit_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<(), TransactionSubmissionError> {
        // we already processed the transaction before the request was received
        if self
            .transaction_status(transaction.tx_hash())
            .await
            .is_some()
        {
            return Err(TransactionReplayError(transaction.tx_hash()));
        }

        let tx_hash = transaction.tx_hash();
        debug!(%tx_hash, "Received mint transaction");

        let mut funding_verifier = FundingVerifier::default();

        let mut pub_keys = Vec::new();

        // Create read-only DB tx so that the read state is consistent
        let mut dbtx = self.db.begin_transaction().await;

        for input in &transaction.inputs {
            let module = self.modules.get_expect(input.module_instance_id());

            let cache = module.build_verification_cache(&[input.clone()]);
            let meta = module
                .validate_input(
                    &FedimintInterconnect { fedimint: self },
                    &mut dbtx.with_module_prefix(input.module_instance_id()),
                    &cache,
                    input,
                )
                .await
                .map_err(|e| TransactionSubmissionError::ModuleError(tx_hash, e))?;

            pub_keys.push(meta.puk_keys);
            funding_verifier.add_input(meta.amount);
        }
        transaction.validate_signature(pub_keys.into_iter().flatten())?;

        for output in &transaction.outputs {
            let amount = self
                .modules
                .get_expect(output.module_instance_id())
                .validate_output(
                    &mut dbtx.with_module_prefix(output.module_instance_id()),
                    output,
                )
                .await
                .map_err(|e| TransactionSubmissionError::ModuleError(tx_hash, e))?;
            funding_verifier.add_output(amount);
        }

        funding_verifier.verify_funding()?;

        self.api_sender
            .send(ApiEvent::Transaction(transaction))
            .await
            .map_err(|_e| TransactionSubmissionError::TxChannelError)?;
        Ok(())
    }

    pub async fn transaction_status(
        &self,
        txid: TransactionId,
    ) -> Option<crate::outcome::TransactionStatus> {
        let mut dbtx = self.db.begin_transaction().await;

        let accepted: Option<AcceptedTransaction> =
            dbtx.get_value(&AcceptedTransactionKey(txid)).await;

        if let Some(accepted) = accepted {
            return Some(
                self.accepted_transaction_status(txid, accepted, &mut dbtx)
                    .await,
            );
        }

        let rejected: Option<String> = self
            .db
            .begin_transaction()
            .await
            .get_value(&RejectedTransactionKey(txid))
            .await;

        if let Some(message) = rejected {
            return Some(TransactionStatus::Rejected(message));
        }

        None
    }

    pub async fn wait_transaction_status(
        &self,
        txid: TransactionId,
    ) -> crate::outcome::TransactionStatus {
        let accepted_key = AcceptedTransactionKey(txid);
        let rejected_key = RejectedTransactionKey(txid);
        tokio::select! {
            (accepted, mut dbtx) = self.db.wait_key_check(&accepted_key, std::convert::identity) => {
                self.accepted_transaction_status(txid, accepted, &mut dbtx).await
            }
            rejected = self.db.wait_key_exists(&rejected_key) => {
                TransactionStatus::Rejected(rejected)
            }
        }
    }

    async fn accepted_transaction_status(
        &self,
        txid: TransactionId,
        accepted: AcceptedTransaction,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> TransactionStatus {
        let mut outputs = Vec::new();
        for (out_idx, output) in accepted.transaction.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                out_idx: out_idx as u64,
            };
            let outcome = self
                .modules
                .get_expect(output.module_instance_id())
                .output_status(
                    &mut dbtx.with_module_prefix(output.module_instance_id()),
                    outpoint,
                    output.module_instance_id(),
                )
                .await
                .expect("the transaction was processed, so must be known");
            outputs.push((&outcome).into())
        }

        TransactionStatus::Accepted {
            epoch: accepted.epoch,
            outputs,
        }
    }

    pub async fn download_config_with_token(
        &self,
        info: WsClientConnectInfo,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> ApiResult<ConfigResponse> {
        let token = self.cfg.local.download_token.clone();

        if info.download_token != token {
            return Err(ApiError::bad_request(
                "Download token not found".to_string(),
            ));
        }

        let times_used = dbtx
            .get_value(&ClientConfigDownloadKey(token.clone()))
            .await
            .unwrap_or_default();

        dbtx.insert_entry(&ClientConfigDownloadKey(token), &(times_used + 1))
            .await;

        if let Some(limit) = self.cfg.local.download_token_limit {
            if times_used > limit {
                return Err(ApiError::bad_request(
                    "Download token used too many times".to_string(),
                ));
            }
        }

        Ok(self.get_config_with_sig(dbtx).await)
    }

    pub async fn epoch_history(&self, epoch: u64) -> Option<SignedEpochOutcome> {
        self.db
            .begin_transaction()
            .await
            .get_value(&EpochHistoryKey(epoch))
            .await
    }

    pub async fn get_epoch_count(&self) -> u64 {
        self.db
            .begin_transaction()
            .await
            .get_value(&LastEpochKey)
            .await
            .map(|ep_hist_key| ep_hist_key.0 + 1)
            .unwrap_or(0)
    }

    pub async fn get_config_with_sig(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> ConfigResponse {
        let mut client = self.client_cfg.clone();
        let maybe_sig = dbtx.get_value(&ClientConfigSignatureKey).await;
        if let Some(SerdeSignature(sig)) = maybe_sig {
            client.client_hash_signature = Some(sig);
        }
        client
    }

    /// Sends an upgrade signal to the fedimint server thread
    pub async fn signal_upgrade(&self) -> Result<(), SendError<ApiEvent>> {
        self.api_sender.send(ApiEvent::UpgradeSignal).await
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
impl HasApiContext<ConsensusApi> for ConsensusApi {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&ConsensusApi, ApiEndpointContext<'_>) {
        let mut db = self.db.clone();
        let mut dbtx = self.db.begin_transaction().await;
        if let Some(id) = id {
            db = self.db.new_isolated(id);
            dbtx = dbtx.new_module_tx(id)
        }
        (
            self,
            ApiEndpointContext::new(
                db,
                dbtx,
                request.auth == Some(self.cfg.private.api_auth.clone()),
            ),
        )
    }
}

#[async_trait]
impl HasApiContext<DynServerModule> for ConsensusApi {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&DynServerModule, ApiEndpointContext<'_>) {
        let (_, context): (&ConsensusApi, _) = self.context(request, id).await;
        (
            self.modules.get_expect(id.expect("required module id")),
            context,
        )
    }
}

pub async fn run_server(cfg: ServerConfig, fedimint: Arc<ConsensusApi>, task_handle: TaskHandle) {
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

fn server_endpoints() -> Vec<ApiEndpoint<ConsensusApi>> {
    vec![
        api_endpoint! {
            "/transaction",
            async |fedimint: &ConsensusApi, _context, serde_transaction: SerdeTransaction| -> TransactionId {
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
            async |fedimint: &ConsensusApi, _context, tx_hash: TransactionId| -> Option<TransactionStatus> {
                debug!(transaction = %tx_hash, "Received request");

                let tx_status = fedimint.transaction_status(tx_hash)
                    .await;

                debug!(transaction = %tx_hash, "Sending outcome");
                Ok(tx_status)
            }
        },
        api_endpoint! {
            "/wait_transaction",
            async |fedimint: &ConsensusApi, _context, tx_hash: TransactionId| -> TransactionStatus {
                debug!(transaction = %tx_hash, "Received request");

                let tx_status = fedimint.wait_transaction_status(tx_hash)
                    .await;

                debug!(transaction = %tx_hash, "Sending outcome");
                Ok(tx_status)
            }
        },
        api_endpoint! {
            "/fetch_epoch_history",
            async |fedimint: &ConsensusApi, _context, epoch: u64| -> SerdeEpochHistory {
                let epoch = fedimint.epoch_history(epoch).await.ok_or_else(|| ApiError::not_found(String::from("epoch not found")))?;
                Ok((&epoch).into())
            }
        },
        api_endpoint! {
            "/fetch_epoch_count",
            async |fedimint: &ConsensusApi, _context, _v: ()| -> u64 {
                Ok(fedimint.get_epoch_count().await)
            }
        },
        api_endpoint! {
            "/config",
            async |fedimint: &ConsensusApi, context, info: WsClientConnectInfo| -> ConfigResponse {
                fedimint.download_config_with_token(info, &mut context.dbtx()).await
            }
        },
        api_endpoint! {
            "/config_hash",
            async |fedimint: &ConsensusApi, context, _v: ()| -> sha256::Hash {
                Ok(fedimint.get_config_with_sig(&mut context.dbtx()).await.consensus_hash)
            }
        },
        api_endpoint! {
            "upgrade",
            async |fedimint: &ConsensusApi, context, _v: ()| -> () {
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
