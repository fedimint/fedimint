//! Implements the client API through which users interact with the federation
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_core::api::{
    ConsensusStatus, PeerConnectionStatus, PeerConsensusStatus, ServerStatus, StatusResponse,
    WsClientConnectInfo,
};
use fedimint_core::config::{ClientConfig, ClientConfigResponse};
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
use jsonrpsee::RpcModule;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use tracing::debug;

use super::peers::PeerStatusChannels;
use crate::config::api::{get_verification_hashes, ApiResult};
use crate::config::ServerConfig;
use crate::consensus::interconnect::FedimintInterconnect;
use crate::consensus::server::LatestContributionByPeer;
use crate::consensus::{
    AcceptedTransaction, ApiEvent, FundingVerifier, TransactionSubmissionError,
};
use crate::db::{
    AcceptedTransactionKey, ClientConfigDownloadKey, ClientConfigSignatureKey, EpochHistoryKey,
    LastEpochKey, RejectedTransactionKey,
};
use crate::fedimint_core::encoding::Encodable;
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

    pub async fn download_client_config(
        &self,
        info: WsClientConnectInfo,
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
        let our_last_contribution = self.get_epoch_count().await;
        let latest_contribution_by_peer = self.latest_contribution_by_peer.read().await.clone();
        let peers_connection_status: HashMap<PeerId, anyhow::Result<PeerConnectionStatus>> =
            self.peer_status_channels.get_all_status().await;
        // How much time we consider a contribution recent for a "grace time".
        // For instance, even if a peer isn't connected right now, if it contributed
        // recently then we won't flag it.
        const MAX_DURATION_FOR_RECENT_CONTRIBUTION: Duration = Duration::from_secs(60);

        Ok(calculate_consensus_status(
            latest_contribution_by_peer,
            our_last_contribution,
            peers_connection_status,
            MAX_DURATION_FOR_RECENT_CONTRIBUTION,
        ))
    }
}

fn calculate_consensus_status(
    latest_contribution_by_peer: LatestContributionByPeer,
    our_last_contribution: u64,
    peers_connection_status: HashMap<PeerId, anyhow::Result<PeerConnectionStatus>>,
    max_duration_for_recent_contribution: Duration,
) -> ConsensusStatus {
    let mut peers = peers_connection_status
        .keys()
        .copied()
        .collect::<HashSet<_>>();
    peers.extend(latest_contribution_by_peer.keys().copied());
    let peer_consensus_status = peers
        .into_iter()
        .map(|peer| {
            let mut consensus_status = PeerConsensusStatus::default();
            let has_recent_contribution;
            if let Some(contribution) = latest_contribution_by_peer.get(&peer) {
                let is_behind_us = contribution.value < our_last_contribution;
                has_recent_contribution =
                    contribution.time.elapsed().unwrap() <= max_duration_for_recent_contribution;
                consensus_status.flagged = is_behind_us && !has_recent_contribution;
                consensus_status.last_contribution = Some(contribution.value);
                let unix_timestamp = contribution
                    .time
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                consensus_status.last_contribution_timestamp_seconds = Some(unix_timestamp);
            } else {
                has_recent_contribution = false;
                consensus_status.flagged = true;
            }
            match peers_connection_status.get(&peer) {
                Some(Err(e)) => {
                    debug!(target: LOG_NET_API, %peer, "Unable to get peer connection status: {e}");
                    consensus_status.flagged |= !has_recent_contribution;
                    consensus_status.connection_status = PeerConnectionStatus::Disconnected;
                }
                Some(Ok(PeerConnectionStatus::Disconnected)) | None => {
                    consensus_status.flagged |= !has_recent_contribution;
                    consensus_status.connection_status = PeerConnectionStatus::Disconnected;
                }
                Some(Ok(PeerConnectionStatus::Connected)) => {
                    consensus_status.connection_status = PeerConnectionStatus::Connected;
                }
            };
            (peer, consensus_status)
        })
        .collect::<HashMap<_, _>>();
    let peers_flagged = peer_consensus_status
        .iter()
        .filter(|(_, status)| status.flagged)
        .count() as u64;
    let peers_online = peer_consensus_status
        .iter()
        .filter(|(_, status)| status.connection_status == PeerConnectionStatus::Connected)
        .count() as u64;
    let peers_offline = peer_consensus_status
        .iter()
        .filter(|(_, status)| status.connection_status == PeerConnectionStatus::Disconnected)
        .count() as u64;
    ConsensusStatus {
        last_contribution: our_last_contribution,
        peers_online,
        peers_offline,
        peers_flagged,
        status_by_peer: peer_consensus_status,
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
            "connection_code",
            async |fedimint: &ConsensusApi, _context,  _v: ()| -> String {
                Ok(fedimint.cfg.get_connect_info().to_string())
            }
        },
        api_endpoint! {
            "config",
            async |fedimint: &ConsensusApi, context, connection_code: String| -> ClientConfigResponse {
                let info = connection_code.parse()
                    .map_err(|_| ApiError::bad_request("Could not parse connection code".to_string()))?;
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
                if context.has_auth() {
                    Ok(get_verification_hashes(&fedimint.cfg))
                } else {
                    Err(ApiError::unauthorized())
                }
            }
        },
    ]
}

/// Very simple cache mostly used to protect endpoints against denial of service
/// attacks
#[derive(Clone)]
pub struct ExpiringCache<T> {
    data: Arc<tokio::sync::Mutex<Option<(T, Instant)>>>,
    duration: std::time::Duration,
}

impl<T: Clone> ExpiringCache<T> {
    pub fn new(duration: std::time::Duration) -> Self {
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

    use fedimint_core::api::ConsensusContribution;
    use fedimint_core::time::now;

    use super::*;
    #[test]
    fn test_server_status_all_ok() {
        let now = now();
        let our_last_contribution = 1;
        let latest_contribution_by_peer = HashMap::from([
            (
                PeerId::from(0),
                ConsensusContribution {
                    value: 1,
                    time: now,
                },
            ),
            (
                PeerId::from(1),
                ConsensusContribution {
                    value: 2,
                    time: now,
                },
            ),
        ]);
        let peers_connection_status = HashMap::from([
            (PeerId::from(0), Ok(PeerConnectionStatus::Connected)),
            (PeerId::from(1), Ok(PeerConnectionStatus::Connected)),
        ]);
        let max_duration_for_recent_contribution = Duration::from_secs(5);
        let result = calculate_consensus_status(
            latest_contribution_by_peer,
            our_last_contribution,
            peers_connection_status,
            max_duration_for_recent_contribution,
        );
        assert_eq!(result.peers_online, 2);
        assert_eq!(result.peers_offline, 0);
        assert_eq!(result.peers_flagged, 0);
        assert!(result.status_by_peer.values().all(|p| !p.flagged));
    }

    #[test]
    fn test_server_status_some_issues_not_flagged() {
        let now = now();
        let our_last_contribution = 3;
        let latest_contribution_by_peer = HashMap::from([
            (
                PeerId::from(0),
                ConsensusContribution {
                    value: 2, // behind us
                    time: now,
                },
            ),
            (
                PeerId::from(1),
                ConsensusContribution {
                    value: 3,
                    time: now,
                },
            ),
        ]);
        let peers_connection_status = HashMap::from([
            (PeerId::from(0), Ok(PeerConnectionStatus::Connected)),
            (PeerId::from(1), Ok(PeerConnectionStatus::Disconnected)), // offline
        ]);
        // we have some "grace time", recent contributions keep the peer from being
        // flagged
        let max_duration_for_recent_contribution = Duration::from_secs(5);
        let result = calculate_consensus_status(
            latest_contribution_by_peer,
            our_last_contribution,
            peers_connection_status,
            max_duration_for_recent_contribution,
        );
        assert_eq!(result.peers_online, 1);
        assert_eq!(result.peers_offline, 1);
        assert_eq!(result.peers_flagged, 0);
        assert!(result.status_by_peer.values().all(|p| !p.flagged));
    }

    #[test]
    fn test_server_status_some_issues_flagged() {
        let now = now();
        let our_last_contribution = 3;
        let latest_contribution_by_peer = HashMap::from([
            (
                PeerId::from(0),
                ConsensusContribution {
                    value: 2, // behind us
                    time: now,
                },
            ),
            (
                PeerId::from(1),
                ConsensusContribution {
                    value: 3,
                    time: now,
                },
            ),
        ]);
        let peers_connection_status = HashMap::from([
            (PeerId::from(0), Ok(PeerConnectionStatus::Connected)),
            (PeerId::from(1), Ok(PeerConnectionStatus::Disconnected)), // offline
        ]);
        // no "grace time", if a peer has some issue its recent contributions won't help
        let max_duration_for_recent_contribution = Duration::from_secs(0);
        let result = calculate_consensus_status(
            latest_contribution_by_peer,
            our_last_contribution,
            peers_connection_status,
            max_duration_for_recent_contribution,
        );
        assert_eq!(result.peers_online, 1);
        assert_eq!(result.peers_offline, 1);
        assert_eq!(result.peers_flagged, 2);
        assert!(result.status_by_peer.values().all(|p| p.flagged));
    }

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
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result = cache
            .get(|| async {
                counter += 1;
                counter
            })
            .await;
        assert_eq!(result, 2);
    }
}
