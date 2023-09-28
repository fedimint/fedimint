//! Implements the client API through which users interact with the federation
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_atomic_broadcast::{SignedBlockKey, SignedBlockPrefix};
use fedimint_core::api::{
    ClientConfigDownloadToken, FederationStatus, InviteCode, PeerConnectionStatus, PeerStatus,
    ServerStatus, StatusResponse,
};
use fedimint_core::backup::ClientBackupKey;
use fedimint_core::block::{Block, SignedBlock};
use fedimint_core::config::{ClientConfig, ClientConfigResponse, JsonWithKind};
use fedimint_core::core::backup::SignedBackupRequest;
use fedimint_core::core::{DynOutputOutcome, ModuleInstanceId};
use fedimint_core::db::{Database, DatabaseTransaction, ModuleDatabaseTransaction};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::audit::{Audit, AuditSummary};
use fedimint_core::module::registry::ServerModuleRegistry;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased, SerdeModuleEncoding,
    SupportedApiVersionsSummary,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskGroup;
use fedimint_core::transaction::Transaction;
use fedimint_core::{OutPoint, PeerId, TransactionId};
use fedimint_logging::LOG_NET_API;
use futures::StreamExt;
use itertools::Itertools;
use jsonrpsee::RpcModule;
use secp256k1_zkp::SECP256K1;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::peers::PeerStatusChannels;
use crate::backup::ClientBackupSnapshot;
use crate::config::api::get_verification_hashes;
use crate::config::ServerConfig;
use crate::consensus::server::LatestContributionByPeer;
use crate::consensus::{FundingVerifier, VerificationCaches};
use crate::db::{
    AcceptedTransactionKey, ClientConfigDownloadKey, ClientConfigDownloadKeyPrefix,
    ClientConfigSignatureKey,
};
use crate::fedimint_core::encoding::Encodable;
use crate::transaction::SerdeTransaction;
use crate::{check_auth, ApiResult, HasApiContext};

pub type SerdeOutputOutcome = SerdeModuleEncoding<DynOutputOutcome>;

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

/// Tracks the usage of invitiation code tokens
///
/// Mostly to serialize the database counter modifications, which would
/// otherwise cause MVCC conflict.
#[derive(Clone)]
pub struct InvitationCodesTracker {
    counts: Arc<tokio::sync::Mutex<BTreeMap<ClientConfigDownloadToken, u64>>>,
    /// Notify on any change `counts` above.
    ///
    /// Multiple invitation codes are possible. Maintaining notifications
    /// per-key seems like a pain, so instead we assume invitation codes are
    /// not in thousands and let the worker task detect the changes against
    /// a local copy.
    ///
    /// `watch` is used as it supports sender disconnection detection which
    /// simplifies task termination.
    counts_changed_tx: Arc<tokio::sync::watch::Sender<()>>,
}

impl InvitationCodesTracker {
    pub async fn new(db: Database, tg: &mut TaskGroup) -> Self {
        let counts: BTreeMap<_, _> = db
            .begin_transaction()
            .await
            .find_by_prefix(&ClientConfigDownloadKeyPrefix)
            .await
            .map(|(k, v)| (k.0, v))
            .collect()
            .await;

        let mut local_counts = counts.clone();
        let counts = Arc::new(tokio::sync::Mutex::new(counts));

        let (tx, mut rx) = tokio::sync::watch::channel(());

        tg.spawn("invitation_codes_tracker", {
            let counts = counts.clone();

            |_| async move {
                while let Ok(()) = rx.changed().await {
                    let changed_counts: Vec<_> = counts
                        .lock()
                        .await
                        .iter()
                        .filter_map(|(token, count)| {
                            if local_counts.get(token).copied().unwrap_or_default() != *count {
                                Some((token.clone(), *count))
                            } else {
                                None
                            }
                        })
                        .collect();

                    let mut dbtx = db.begin_transaction().await;

                    for (token, count) in changed_counts {
                        dbtx.insert_entry(&ClientConfigDownloadKey(token.clone()), &count)
                            .await;
                        local_counts.insert(token, count);
                    }

                    dbtx.commit_tx().await;
                }
            }
        })
        .await;

        Self {
            counts,
            counts_changed_tx: Arc::new(tx),
        }
    }

    pub async fn use_token(
        &self,
        token: &ClientConfigDownloadToken,
        limit: Option<u64>,
    ) -> Result<(), ()> {
        let mut lock = self.counts.lock().await;

        let entry = lock.entry(token.clone()).or_default();

        if limit.map(|limit| limit <= *entry).unwrap_or(false) {
            return Err(());
        }

        *entry += 1;

        drop(lock);

        self.counts_changed_tx
            .send(())
            .expect("invitations code tracker task panicked");

        Ok(())
    }
}

#[derive(Clone)]
pub struct ConsensusApi {
    /// Our server configuration
    pub cfg: ServerConfig,
    /// Database for serving the API
    pub db: Database,

    pub invitation_codes_tracker: InvitationCodesTracker,

    /// Modules registered with the federation
    pub modules: ServerModuleRegistry,
    /// Cached client config
    pub client_cfg: ClientConfig,
    /// For sending API events to consensus such as transactions
    pub submission_sender: async_channel::Sender<Vec<u8>>,
    pub peer_status_channels: PeerStatusChannels,
    pub latest_contribution_by_peer: Arc<RwLock<LatestContributionByPeer>>,
    pub consensus_status_cache: ExpiringCache<ApiResult<FederationStatus>>,
    pub supported_api_versions: SupportedApiVersionsSummary,
}

impl ConsensusApi {
    pub fn api_versions_summary(&self) -> &SupportedApiVersionsSummary {
        &self.supported_api_versions
    }

    pub async fn submit_transaction(&self, transaction: Transaction) -> anyhow::Result<()> {
        let txid = transaction.tx_hash();

        debug!(%txid, "Received mint transaction");

        // we already processed the transaction before the request was received
        if self
            .db
            .begin_transaction()
            .await
            .get_value(&AcceptedTransactionKey(txid))
            .await
            .is_some()
        {
            return Ok(());
        }

        // Create read-only DB tx so that the read state is consistent
        let mut dbtx = self.db.begin_transaction().await;

        // We ignore any writes, as we only verify if the transaction is valid here
        dbtx.ignore_uncommitted();

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

        self.submission_sender
            .send(
                ConsensusItem::Transaction(transaction)
                    .consensus_encode_to_vec()
                    .expect("Infallible"),
            )
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

    pub async fn await_transaction(
        &self,
        txid: TransactionId,
    ) -> (Vec<ModuleInstanceId>, DatabaseTransaction) {
        self.db
            .wait_key_check(&AcceptedTransactionKey(txid), std::convert::identity)
            .await
    }

    pub async fn await_output_outcome(&self, outpoint: OutPoint) -> Result<SerdeOutputOutcome> {
        let (module_ids, mut dbtx) = self.await_transaction(outpoint.txid).await;

        let module_id = module_ids
            .into_iter()
            .nth(outpoint.out_idx as usize)
            .ok_or(anyhow!("Outpoint index out of bounds {:?}", outpoint))?;

        let outcome = self
            .modules
            .get_expect(module_id)
            .output_status(&mut dbtx.with_module_prefix(module_id), outpoint, module_id)
            .await
            .expect("The transaction is accepted");

        Ok((&outcome).into())
    }

    pub async fn get_block_count(&self) -> u64 {
        self.db
            .begin_transaction()
            .await
            .find_by_prefix(&SignedBlockPrefix)
            .await
            .count()
            .await as u64
    }

    pub async fn get_block(&self, index: u64) -> Option<SignedBlock> {
        self.db
            .begin_transaction()
            .await
            .get_value(&SignedBlockKey(index))
            .await
    }

    pub async fn download_client_config(&self, info: InviteCode) -> ApiResult<ClientConfig> {
        let token = self.cfg.local.download_token.clone();

        if self.cfg.consensus.federation_id() != info.id {
            return Err(ApiError::bad_request("Wrong Federation Id".to_string()));
        }

        if self.cfg.local.identity != info.peer_id {
            return Err(ApiError::bad_request("Wrong Peer Id".to_string()));
        }
        if info.download_token != token {
            return Err(ApiError::bad_request(
                "Download token not found".to_string(),
            ));
        }

        if self
            .invitation_codes_tracker
            .use_token(&token, self.cfg.local.download_token_limit)
            .await
            .is_err()
        {
            return Err(ApiError::bad_request(
                "Download token used too many times".to_string(),
            ));
        }

        Ok(self.client_cfg.clone())
    }

    pub async fn get_federation_status(&self) -> ApiResult<FederationStatus> {
        let peers_connection_status = self.peer_status_channels.get_all_status().await;
        let latest_contribution_by_peer = self.latest_contribution_by_peer.read().await.clone();
        let epoch_count = 0;

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

                let consensus_status = PeerStatus {
                    last_contribution,
                    flagged,
                    connection_status,
                };

                (peer, consensus_status)
            })
            .collect::<HashMap<PeerId, PeerStatus>>();

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

        Ok(FederationStatus {
            // the naming is in preparation for aleph bft since we will switch to
            // the session count here and want to keep the public API stable
            session_count: epoch_count,
            peers_online,
            peers_offline,
            peers_flagged,
            status_by_peer,
        })
    }

    async fn get_federation_audit(&self) -> ApiResult<AuditSummary> {
        let mut dbtx = self.db.begin_transaction().await;
        let mut audit = Audit::default();
        let mut module_instance_id_to_kind: HashMap<ModuleInstanceId, String> = HashMap::new();
        for (module_instance_id, kind, module) in self.modules.iter_modules() {
            module_instance_id_to_kind.insert(module_instance_id, kind.as_str().to_string());
            module
                .audit(
                    &mut dbtx.with_module_prefix(module_instance_id),
                    &mut audit,
                    module_instance_id,
                )
                .await
        }
        Ok(AuditSummary::from_audit(
            &audit,
            &module_instance_id_to_kind,
        ))
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
                let transaction = serde_transaction
                    .try_into_inner(&fedimint.modules.decoder_registry())
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;

                let tx_id = transaction.tx_hash();

                fedimint.submit_transaction(transaction)
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;

                Ok(tx_id)
            }
        },
        api_endpoint! {
            "wait_transaction",
            async |fedimint: &ConsensusApi, _context, tx_hash: TransactionId| -> TransactionId {
                debug!(transaction = %tx_hash, "Received request");

                fedimint.await_transaction(tx_hash).await;

                debug!(transaction = %tx_hash, "Sending outcome");

                Ok(tx_hash)
            }
        },
        api_endpoint! {
            "await_output_outcome",
            async |fedimint: &ConsensusApi, _context, outpoint: OutPoint| -> SerdeOutputOutcome {
                let outcome = fedimint
                    .await_output_outcome(outpoint)
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;

                Ok(outcome)
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
                let client_config = fedimint.download_client_config(info).await?;
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
            "status",
            async |fedimint: &ConsensusApi, _context, _v: ()| -> StatusResponse {
                let consensus_status = fedimint
                    .consensus_status_cache
                    .get(|| fedimint.get_federation_status())
                    .await?;
                Ok(StatusResponse {
                    server: ServerStatus::ConsensusRunning,
                    federation: Some(consensus_status)
                })
            }
        },
        api_endpoint! {
            "get_block_count",
            async |fedimint: &ConsensusApi, _context, _v: ()| -> u64 {
                Ok(fedimint.get_block_count().await)
            }
        },
        api_endpoint! {
            "get_block",
            async |fedimint: &ConsensusApi, _context, index: u64| -> Option<Block> {
                Ok(fedimint.get_block(index).await.map(|sb| sb.block))
            }
        },
        api_endpoint! {
            "audit",
            async |fedimint: &ConsensusApi, context, _v: ()| -> AuditSummary {
                check_auth(context)?;
                Ok(fedimint.get_federation_audit().await?)
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
            async |_fedimint: &ConsensusApi, context, _v: ()| -> () {
                check_auth(context)?;
                Ok(())
            }
        },
        api_endpoint! {
            "modules_config_json",
            async |fedimint: &ConsensusApi, _context, _v: ()| -> BTreeMap<ModuleInstanceId, JsonWithKind> {
                Ok(fedimint.cfg.consensus.modules_json.clone())
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
