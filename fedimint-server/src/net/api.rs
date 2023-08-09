//! Implements the client API through which users interact with the federation
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_core::api::{
    ConsensusStatus, InviteCode, PeerConnectionStatus, PeerConsensusStatus, ServerStatus,
    StatusResponse,
};
use fedimint_core::backup::ClientBackupKey;
use fedimint_core::config::{ClientConfig, ClientConfigResponse};
use fedimint_core::core::backup::SignedBackupRequest;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction, ModuleDatabaseTransaction};
use fedimint_core::epoch::{SerdeEpochHistory, SignedEpochOutcome};
use fedimint_core::module::registry::ServerModuleRegistry;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased,
    SupportedApiVersionsSummary,
};
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::server::DynServerModule;
use fedimint_core::transaction::Transaction;
use fedimint_core::{OutPoint, PeerId, TransactionId};
use fedimint_logging::LOG_NET_API;
use itertools::Itertools;
use jsonrpsee::RpcModule;
use secp256k1_zkp::SECP256K1;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::peers::PeerStatusChannels;
use crate::backup::ClientBackupSnapshot;
use crate::config::api::get_verification_hashes;
use crate::config::ServerConfig;
use crate::consensus::server::LatestContributionByPeer;
use crate::consensus::{ApiEvent, FundingVerifier, VerificationCaches};
use crate::db::{
    AcceptedTransactionKey, ClientConfigDownloadKey, ClientConfigSignatureKey, EpochHistoryKey,
    LastEpochKey,
};
use crate::fedimint_core::encoding::Encodable;
use crate::transaction::SerdeTransaction;
use crate::{check_auth, ApiResult, HasApiContext};

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
    /// Cached client config
    pub client_cfg: ClientConfig,
    /// For sending API events to consensus such as transactions
    pub api_sender: Sender<ApiEvent>,
    pub peer_status_channels: PeerStatusChannels,
    pub latest_contribution_by_peer: Arc<RwLock<LatestContributionByPeer>>,
    pub consensus_status_cache: ExpiringCache<ApiResult<ConsensusStatus>>,
    pub supported_api_versions: SupportedApiVersionsSummary,
}

impl ConsensusApi {
    pub fn api_versions_summary(&self) -> &SupportedApiVersionsSummary {
        &self.supported_api_versions
    }

    pub async fn submit_transaction(&self, transaction: Transaction) -> anyhow::Result<()> {
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

        // Create read-only DB tx so that the read state is consistent
        let mut dbtx = self.db.begin_transaction().await;

        let txid = transaction.tx_hash();
        let caches = self.build_verification_caches(transaction.clone());

        let mut funding_verifier = FundingVerifier::default();
        let mut public_keys = Vec::new();

        for input in transaction.inputs.iter() {
            let meta = self
                .modules
                .get_expect(input.module_instance_id())
                .process_input(
                    &mut dbtx.with_module_prefix(input.module_instance_id()),
                    input,
                    caches.get_cache(input.module_instance_id()),
                )
                .await?;

            funding_verifier.add_input(meta.amount);
            public_keys.push(meta.pub_keys);
        }

        transaction.validate_signature(public_keys.into_iter().flatten())?;

        for (output, out_idx) in transaction.outputs.iter().zip(0u64..) {
            let amount = self
                .modules
                .get_expect(output.module_instance_id())
                .process_output(
                    &mut dbtx.with_module_prefix(output.module_instance_id()),
                    output,
                    OutPoint { txid, out_idx },
                )
                .await?;

            funding_verifier.add_output(amount);
        }

        funding_verifier.verify_funding()?;

        self.api_sender
            .send(ApiEvent::Transaction(transaction))
            .await?;

        Ok(())
    }

    fn build_verification_caches(&self, transaction: Transaction) -> VerificationCaches {
        let module_inputs = transaction
            .inputs
            .into_iter()
            .into_group_map_by(|input| input.module_instance_id());

        let caches = module_inputs
            .into_iter()
            .map(|(module_key, inputs)| {
                let module = self.modules.get_expect(module_key);
                (module_key, module.build_verification_cache(&inputs))
            })
            .collect();

        VerificationCaches { caches }
    }

    pub async fn transaction_status(&self, txid: TransactionId) -> Option<TransactionStatus> {
        let mut dbtx = self.db.begin_transaction().await;

        let module_ids = dbtx.get_value(&AcceptedTransactionKey(txid)).await?;

        let status = self
            .accepted_transaction_status(txid, module_ids, &mut dbtx)
            .await;

        Some(status)
    }

    pub async fn wait_transaction_status(&self, txid: TransactionId) -> TransactionStatus {
        let (outputs, mut dbtx) = self
            .db
            .wait_key_check(&AcceptedTransactionKey(txid), std::convert::identity)
            .await;

        self.accepted_transaction_status(txid, outputs, &mut dbtx)
            .await
    }

    async fn accepted_transaction_status(
        &self,
        txid: TransactionId,
        module_ids: Vec<ModuleInstanceId>,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> TransactionStatus {
        let mut outputs = Vec::new();

        for (module_id, out_idx) in module_ids.into_iter().zip(0u64..) {
            let outcome = self
                .modules
                .get_expect(module_id)
                .output_status(
                    &mut dbtx.with_module_prefix(module_id),
                    OutPoint { txid, out_idx },
                    module_id,
                )
                .await
                .expect("the transaction was accepted");

            outputs.push((&outcome).into())
        }

        TransactionStatus::Accepted { epoch: 0, outputs }
    }

    pub async fn download_client_config(
        &self,
        info: InviteCode,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> ApiResult<ClientConfig> {
        let token = self.cfg.local.download_token.clone();

        if info.download_token != token {
            return Err(ApiError::bad_request(
                "Download token not found".to_string(),
            ));
        }

        let times_used = dbtx
            .get_value(&ClientConfigDownloadKey(token.clone()))
            .await
            .unwrap_or_default()
            + 1;

        dbtx.insert_entry(&ClientConfigDownloadKey(token), &times_used)
            .await;

        if let Some(limit) = self.cfg.local.download_token_limit {
            if times_used > limit {
                return Err(ApiError::bad_request(
                    "Download token used too many times".to_string(),
                ));
            }
        }

        Ok(self.client_cfg.clone())
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

    pub async fn get_consensus_status(&self) -> ApiResult<ConsensusStatus> {
        let peers_connection_status = self.peer_status_channels.get_all_status().await;
        let latest_contribution_by_peer = self.latest_contribution_by_peer.read().await.clone();
        let epoch_count = self.get_epoch_count().await;

        let status_by_peer = peers_connection_status
            .into_iter()
            .map(|(peer, connection_status)| {
                let last_contribution = latest_contribution_by_peer.get(&peer).cloned();
                let flagged = last_contribution.unwrap_or(0) + 1 < epoch_count;
                let connection_status = match connection_status {
                    Ok(status) => status,
                    Err(e) => {
                        debug!(target: LOG_NET_API, %peer, "Unable to get peer connection status: {e}");
                        PeerConnectionStatus::Disconnected
                    }
                };

                let consensus_status = PeerConsensusStatus {
                    last_contribution,
                    flagged,
                    connection_status,
                };

                (peer, consensus_status)
            })
            .collect::<HashMap<PeerId, PeerConsensusStatus>>();

        let peers_flagged = status_by_peer
            .values()
            .filter(|status| status.flagged)
            .count() as u64;

        let peers_online = status_by_peer
            .values()
            .filter(|status| status.connection_status == PeerConnectionStatus::Connected)
            .count() as u64;

        let peers_offline = status_by_peer
            .values()
            .filter(|status| status.connection_status == PeerConnectionStatus::Disconnected)
            .count() as u64;

        Ok(ConsensusStatus {
            // the naming is in preparation for aleph bft since we will switch to
            // the session count here and want to keep the public API stable
            session_count: epoch_count,
            peers_online,
            peers_offline,
            peers_flagged,
            status_by_peer,
        })
    }

    async fn handle_backup_request(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        request: SignedBackupRequest,
    ) -> Result<(), ApiError> {
        let request = request
            .verify_valid(SECP256K1)
            .map_err(|_| ApiError::bad_request("invalid request".into()))?;

        debug!(target: LOG_NET_API, id = %request.id, len = request.payload.len(), "Received client backup request");
        if let Some(prev) = dbtx.get_value(&ClientBackupKey(request.id)).await {
            if request.timestamp <= prev.timestamp {
                debug!(id = %request.id, len = request.payload.len(), "Received client backup request with old timestamp - ignoring");
                return Err(ApiError::bad_request("timestamp too small".into()));
            }
        }

        info!(target: LOG_NET_API, id = %request.id, len = request.payload.len(), "Storing new client backup");
        dbtx.insert_entry(
            &ClientBackupKey(request.id),
            &ClientBackupSnapshot {
                timestamp: request.timestamp,
                data: request.payload.to_vec(),
            },
        )
        .await;

        Ok(())
    }

    async fn handle_recover_request(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        id: secp256k1_zkp::XOnlyPublicKey,
    ) -> Option<ClientBackupSnapshot> {
        dbtx.get_value(&ClientBackupKey(id)).await
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
            "invite_code",
            async |fedimint: &ConsensusApi, _context,  _v: ()| -> String {
                Ok(fedimint.cfg.get_invite_code().to_string())
            }
        },
        api_endpoint! {
            "config",
            async |fedimint: &ConsensusApi, context, invite_code: String| -> ClientConfigResponse {
                let info = invite_code.parse()
                    .map_err(|_| ApiError::bad_request("Could not parse invite code".to_string()))?;
                let future = context.wait_key_exists(ClientConfigSignatureKey);
                let signature = future.await;
                let client_config = fedimint.download_client_config(info, &mut context.dbtx()).await?;
                Ok(ClientConfigResponse{
                    client_config,
                    signature
                })
            }
        },
        api_endpoint! {
            "config_hash",
            async |fedimint: &ConsensusApi, _context, _v: ()| -> sha256::Hash {
                Ok(fedimint.cfg.consensus.consensus_hash())
            }
        },
        api_endpoint! {
            "upgrade",
            async |fedimint: &ConsensusApi, context, _v: ()| -> () {
               check_auth(context)?;
               fedimint.signal_upgrade().await.map_err(|_| ApiError::server_error("Unable to send signal to server".to_string()))?;
               Ok(())
            }
        },
        api_endpoint! {
            "process_outcome",
            async |fedimint: &ConsensusApi, context, outcome: SerdeEpochHistory| -> () {
                check_auth(context)?;
                fedimint.force_process_outcome(outcome).await
                  .map_err(|_| ApiError::server_error("Unable to send signal to server".to_string()))?;
                Ok(())
            }
        },
        api_endpoint! {
            "status",
            async |fedimint: &ConsensusApi, _context, _v: ()| -> StatusResponse {
                let consensus_status = fedimint
                    .consensus_status_cache
                    .get(|| fedimint.get_consensus_status())
                    .await?;
                Ok(StatusResponse {
                    server: ServerStatus::ConsensusRunning,
                    consensus: Some(consensus_status)
                })
            }
        },
        api_endpoint! {
            "get_verify_config_hash",
            async |fedimint: &ConsensusApi, context, _v: ()| -> BTreeMap<PeerId, sha256::Hash> {
                check_auth(context)?;
                Ok(get_verification_hashes(&fedimint.cfg))
            }
        },
        api_endpoint! {
            "backup",
            async |fedimint: &ConsensusApi, context, request: SignedBackupRequest| -> () {
                fedimint
                    .handle_backup_request(&mut context.dbtx(), request).await?;
                Ok(())

            }
        },
        api_endpoint! {
            "recover",
            async |fedimint: &ConsensusApi, context, id: secp256k1_zkp::XOnlyPublicKey| -> Option<ClientBackupSnapshot> {
                Ok(fedimint
                    .handle_recover_request(&mut context.dbtx(), id).await)
            }
        },
        api_endpoint! {
            "auth",
            async |_config: &ConsensusApi, context, _v: ()| -> () {
                check_auth(context)?;
                Ok(())
            }
        },
    ]
}

/// Very simple cache mostly used to protect endpoints against denial of service
/// attacks
#[derive(Clone)]
pub struct ExpiringCache<T> {
    data: Arc<tokio::sync::Mutex<Option<(T, Instant)>>>,
    duration: Duration,
}

impl<T: Clone> ExpiringCache<T> {
    pub fn new(duration: Duration) -> Self {
        Self {
            data: Arc::new(tokio::sync::Mutex::new(None)),
            duration,
        }
    }

    pub async fn get<Fut>(&self, f: impl FnOnce() -> Fut) -> T
    where
        Fut: futures::Future<Output = T>,
    {
        let mut data = self.data.lock().await;
        if let Some((data, time)) = data.as_ref() {
            if time.elapsed() < self.duration {
                return data.clone();
            }
        }
        let new_data = f().await;
        *data = Some((new_data.clone(), Instant::now()));
        new_data
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fedimint_core::task;

    use crate::net::api::ExpiringCache;

    #[tokio::test]
    async fn test_expiring_cache() {
        let cache = ExpiringCache::new(Duration::from_secs(1));
        let mut counter = 0;
        let result = cache
            .get(|| async {
                counter += 1;
                counter
            })
            .await;
        assert_eq!(result, 1);
        let result = cache
            .get(|| async {
                counter += 1;
                counter
            })
            .await;
        assert_eq!(result, 1);
        task::sleep(Duration::from_secs(2)).await;
        let result = cache
            .get(|| async {
                counter += 1;
                counter
            })
            .await;
        assert_eq!(result, 2);
    }
}
