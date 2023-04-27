//! Implements the client API through which users interact with the federation
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_core::admin_client::ServerStatus;
use fedimint_core::api::WsClientConnectInfo;
use fedimint_core::config::ClientConfigResponse;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction, ModuleDatabaseTransaction};
use fedimint_core::epoch::{SerdeEpochHistory, SerdeSignature, SignedEpochOutcome};
use fedimint_core::module::registry::ServerModuleRegistry;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased,
    SupportedApiVersionsSummary,
};
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::server::DynServerModule;
use fedimint_core::transaction::Transaction;
use fedimint_core::{OutPoint, TransactionId};
use jsonrpsee::RpcModule;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::Sender;
use tracing::debug;

use crate::config::api::ApiResult;
use crate::config::ServerConfig;
use crate::consensus::interconnect::FedimintInterconnect;
use crate::consensus::{
    AcceptedTransaction, ApiEvent, FundingVerifier, TransactionSubmissionError,
};
use crate::db::{
    AcceptedTransactionKey, ClientConfigDownloadKey, ClientConfigSignatureKey, EpochHistoryKey,
    LastEpochKey, RejectedTransactionKey,
};
use crate::transaction::SerdeTransaction;
use crate::HasApiContext;

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

#[derive(Clone)]
pub struct ConsensusApi {
    /// Our server configuration
    pub cfg: ServerConfig,
    /// Database for serving the API
    pub db: Database,
    /// Modules registered with the federation
    pub modules: ServerModuleRegistry,
    /// Cached client config response
    pub client_cfg: ClientConfigResponse,
    /// For sending API events to consensus such as transactions
    pub api_sender: Sender<ApiEvent>,

    pub supported_api_versions: SupportedApiVersionsSummary,
}

impl ConsensusApi {
    pub fn api_versions_summary(&self) -> &SupportedApiVersionsSummary {
        &self.supported_api_versions
    }

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
            return Ok(());
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
    ) -> ApiResult<ClientConfigResponse> {
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
    ) -> ClientConfigResponse {
        let mut client = self.client_cfg.clone();
        let maybe_sig = dbtx.get_value(&ClientConfigSignatureKey).await;
        if let Some(SerdeSignature(sig)) = maybe_sig {
            client.signature = Some(sig);
        }
        client
    }

    /// Sends an upgrade signal to the fedimint server thread
    pub async fn signal_upgrade(&self) -> Result<(), SendError<ApiEvent>> {
        self.api_sender.send(ApiEvent::UpgradeSignal).await
    }

    /// Force process an outcome
    pub async fn force_process_outcome(&self, outcome: SerdeEpochHistory) -> ApiResult<()> {
        let event = outcome
            .try_into_inner(&self.modules.decoder_registry())
            .map_err(|_| ApiError::bad_request("Unable to decode outcome".to_string()))?;
        self.api_sender
            .send(ApiEvent::ForceProcessOutcome(event.outcome))
            .await
            .map_err(|_| ApiError::server_error("Unable send event".to_string()))
    }
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
                request.auth.clone(),
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

pub fn server_endpoints() -> Vec<ApiEndpoint<ConsensusApi>> {
    vec![
        api_endpoint! {
            "version",
            async |fedimint: &ConsensusApi, _context, _v: ()| -> SupportedApiVersionsSummary {
                Ok(fedimint.api_versions_summary().to_owned())
            }
        },
        api_endpoint! {
            "transaction",
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
            "fetch_transaction",
            async |fedimint: &ConsensusApi, _context, tx_hash: TransactionId| -> Option<TransactionStatus> {
                debug!(transaction = %tx_hash, "Received request");

                let tx_status = fedimint.transaction_status(tx_hash)
                    .await;

                debug!(transaction = %tx_hash, "Sending outcome");
                Ok(tx_status)
            }
        },
        api_endpoint! {
            "wait_transaction",
            async |fedimint: &ConsensusApi, _context, tx_hash: TransactionId| -> TransactionStatus {
                debug!(transaction = %tx_hash, "Received request");

                let tx_status = fedimint.wait_transaction_status(tx_hash)
                    .await;

                debug!(transaction = %tx_hash, "Sending outcome");
                Ok(tx_status)
            }
        },
        api_endpoint! {
            "fetch_epoch_history",
            async |fedimint: &ConsensusApi, _context, epoch: u64| -> SerdeEpochHistory {
                let epoch = fedimint.epoch_history(epoch).await
                  .ok_or_else(|| ApiError::not_found(format!("epoch {epoch} not found")))?;
                Ok((&epoch).into())
            }
        },
        api_endpoint! {
            "fetch_epoch_count",
            async |fedimint: &ConsensusApi, _context, _v: ()| -> u64 {
                Ok(fedimint.get_epoch_count().await)
            }
        },
        api_endpoint! {
            "config",
            async |fedimint: &ConsensusApi, context, info: WsClientConnectInfo| -> ClientConfigResponse {
                fedimint.download_config_with_token(info, &mut context.dbtx()).await
            }
        },
        api_endpoint! {
            "config_hash",
            async |fedimint: &ConsensusApi, context, _v: ()| -> sha256::Hash {
                Ok(fedimint.get_config_with_sig(&mut context.dbtx()).await.client_config.consensus_hash())
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
        api_endpoint! {
            "process_outcome",
            async |fedimint: &ConsensusApi, context, outcome: SerdeEpochHistory| -> () {
                if context.has_auth() {
                    fedimint.force_process_outcome(outcome).await
                      .map_err(|_| ApiError::server_error("Unable to send signal to server".to_string()))?;
                    Ok(())
                } else {
                    Err(ApiError::unauthorized())
                }
            }
        },
        api_endpoint! {
            "status",
            async |_fedimint: &ConsensusApi, context, _v: ()| -> ServerStatus {
                if context.has_auth() {
                    Ok(ServerStatus::ConsensusRunning)
                } else {
                    Err(ApiError::unauthorized())
                }
            }
        },
    ]
}
