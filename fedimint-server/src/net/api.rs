//! Implements the client API through which users interact with the federation
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_aead::{encrypt, get_encryption_key, random_salt};
use fedimint_core::api::{
    FederationStatus, GuardianConfigBackup, PeerConnectionStatus, PeerStatus, ServerStatus,
    StatusResponse,
};
use fedimint_core::backup::{ClientBackupKey, ClientBackupSnapshot};
use fedimint_core::config::{ClientConfig, JsonWithKind};
use fedimint_core::core::backup::{SignedBackupRequest, BACKUP_REQUEST_MAX_PAYLOAD_SIZE_BYTES};
use fedimint_core::core::{DynOutputOutcome, ModuleInstanceId};
use fedimint_core::db::{
    Committable, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::endpoint_constants::{
    AUDIT_ENDPOINT, AUTH_ENDPOINT, AWAIT_OUTPUT_OUTCOME_ENDPOINT, AWAIT_SESSION_OUTCOME_ENDPOINT,
    AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT, AWAIT_TRANSACTION_ENDPOINT, BACKUP_ENDPOINT,
    CLIENT_CONFIG_ENDPOINT, FEDERATION_ID_ENDPOINT, GUARDIAN_CONFIG_BACKUP_ENDPOINT,
    INVITE_CODE_ENDPOINT, MODULES_CONFIG_JSON_ENDPOINT, RECOVER_ENDPOINT,
    SERVER_CONFIG_CONSENSUS_HASH_ENDPOINT, SESSION_COUNT_ENDPOINT, SESSION_STATUS_ENDPOINT,
    STATUS_ENDPOINT, SUBMIT_TRANSACTION_ENDPOINT, VERIFY_CONFIG_HASH_ENDPOINT, VERSION_ENDPOINT,
};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::audit::{Audit, AuditSummary};
use fedimint_core::module::registry::ServerModuleRegistry;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased, ApiVersion,
    SerdeModuleEncoding, SupportedApiVersionsSummary,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::session_outcome::{SessionOutcome, SessionStatus, SignedSessionOutcome};
use fedimint_core::transaction::{SerdeTransaction, Transaction, TransactionError};
use fedimint_core::{OutPoint, PeerId, TransactionId};
use fedimint_logging::LOG_NET_API;
use futures::StreamExt;
use jsonrpsee::RpcModule;
use secp256k1_zkp::SECP256K1;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::peers::PeerStatusChannels;
use crate::config::io::{
    CONSENSUS_CONFIG, ENCRYPTED_EXT, JSON_EXT, LOCAL_CONFIG, PRIVATE_CONFIG, SALT_FILE,
};
use crate::config::ServerConfig;
use crate::consensus::process_transaction_with_dbtx;
use crate::consensus::server::{get_finished_session_count_static, LatestContributionByPeer};
use crate::db::{AcceptedItemPrefix, AcceptedTransactionKey, SignedSessionOutcomeKey};
use crate::fedimint_core::encoding::Encodable;
use crate::metrics::{BACKUP_WRITE_SIZE_BYTES, STORED_BACKUPS_COUNT};
use crate::{check_auth, get_verification_hashes, ApiResult, HasApiContext};

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
    pub submission_sender: async_channel::Sender<ConsensusItem>,
    pub peer_status_channels: PeerStatusChannels,
    pub latest_contribution_by_peer: Arc<RwLock<LatestContributionByPeer>>,
    pub consensus_status_cache: ExpiringCache<ApiResult<FederationStatus>>,
    pub supported_api_versions: SupportedApiVersionsSummary,
}

impl ConsensusApi {
    pub fn api_versions_summary(&self) -> &SupportedApiVersionsSummary {
        &self.supported_api_versions
    }

    // we want to return an error if and only if the submitted transaction is
    // invalid and will be rejected if we were to submit it to consensus
    pub async fn submit_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<TransactionId, TransactionError> {
        let txid = transaction.tx_hash();

        debug!(%txid, "Received mint transaction");

        // we already processed the transaction before
        if self
            .db
            .begin_transaction()
            .await
            .get_value(&AcceptedTransactionKey(txid))
            .await
            .is_some()
        {
            return Ok(txid);
        }

        // Create read-only DB tx so that the read state is consistent
        let mut dbtx = self.db.begin_transaction_nc().await;

        // We ignore any writes, as we only verify if the transaction is valid here
        dbtx.ignore_uncommitted();

        process_transaction_with_dbtx(self.modules.clone(), &mut dbtx, transaction.clone()).await?;

        self.submission_sender
            .send(ConsensusItem::Transaction(transaction))
            .await
            .ok();

        Ok(txid)
    }

    pub async fn await_transaction(
        &self,
        txid: TransactionId,
    ) -> (Vec<ModuleInstanceId>, DatabaseTransaction<'_, Committable>) {
        self.db
            .wait_key_check(&AcceptedTransactionKey(txid), std::convert::identity)
            .await
    }

    pub async fn await_output_outcome(
        &self,
        outpoint: OutPoint,
    ) -> Result<SerdeModuleEncoding<DynOutputOutcome>> {
        let (module_ids, mut dbtx) = self.await_transaction(outpoint.txid).await;

        let module_id = module_ids
            .into_iter()
            .nth(outpoint.out_idx as usize)
            .ok_or(anyhow!("Outpoint index out of bounds {:?}", outpoint))?;

        let outcome = self
            .modules
            .get_expect(module_id)
            .output_status(
                &mut dbtx.to_ref_with_prefix_module_id(module_id).into_nc(),
                outpoint,
                module_id,
            )
            .await
            .expect("The transaction is accepted");

        Ok((&outcome).into())
    }

    pub async fn session_count(&self) -> u64 {
        get_finished_session_count_static(&mut self.db.begin_transaction_nc().await).await
    }

    pub async fn await_signed_session_outcome(&self, index: u64) -> SignedSessionOutcome {
        self.db
            .wait_key_check(&SignedSessionOutcomeKey(index), std::convert::identity)
            .await
            .0
    }

    pub async fn session_status(&self, session_index: u64) -> SessionStatus {
        let mut dbtx = self.db.begin_transaction_nc().await;

        match session_index.cmp(&get_finished_session_count_static(&mut dbtx).await) {
            Ordering::Greater => SessionStatus::Initial,
            Ordering::Equal => SessionStatus::Pending(
                dbtx.find_by_prefix(&AcceptedItemPrefix)
                    .await
                    .map(|entry| entry.1)
                    .collect()
                    .await,
            ),
            Ordering::Less => SessionStatus::Complete(
                dbtx.get_value(&SignedSessionOutcomeKey(session_index))
                    .await
                    .expect("There are no gaps in session outcomes")
                    .session_outcome,
            ),
        }
    }

    pub async fn get_federation_status(&self) -> ApiResult<FederationStatus> {
        let peers_connection_status = self.peer_status_channels.get_all_status().await;
        let latest_contribution_by_peer = self.latest_contribution_by_peer.read().await.clone();
        let session_count = self.session_count().await;

        let status_by_peer = peers_connection_status
            .into_iter()
            .map(|(peer, connection_status)| {
                let last_contribution = latest_contribution_by_peer.get(&peer).cloned();
                let flagged = last_contribution.unwrap_or(0) + 1 < session_count;
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
            session_count,
            peers_online,
            peers_offline,
            peers_flagged,
            status_by_peer,
        })
    }

    async fn get_federation_audit(&self) -> ApiResult<AuditSummary> {
        let mut dbtx = self.db.begin_transaction_nc().await;
        // Writes are related to compacting audit keys, which we can safely ignore
        // within an API request since the compaction will happen when constructing an
        // audit in the consensus server
        dbtx.ignore_uncommitted();

        let mut audit = Audit::default();
        let mut module_instance_id_to_kind: HashMap<ModuleInstanceId, String> = HashMap::new();
        for (module_instance_id, kind, module) in self.modules.iter_modules() {
            module_instance_id_to_kind.insert(module_instance_id, kind.as_str().to_string());
            module
                .audit(
                    &mut dbtx.to_ref_with_prefix_module_id(module_instance_id),
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

    /// Uses the in-memory config to write a config backup tar archive that
    /// guardians can download. Private keys are encrypted with the guardian
    /// password, so it should be safe to store anywhere, this also means the
    /// backup is useless without the password.
    async fn get_guardian_config_backup(
        &self,
        password: String,
    ) -> ApiResult<GuardianConfigBackup> {
        let mut tar_archive_builder = tar::Builder::new(Vec::new());

        let mut append = |name: &Path, data: &[u8]| {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).expect("Error setting path");
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_archive_builder
                .append(&header, data)
                .expect("Error adding data to tar archive");
        };

        append(
            &PathBuf::from(LOCAL_CONFIG).with_extension(JSON_EXT),
            &serde_json::to_vec(&self.cfg.local).expect("Error encoding local config"),
        );

        append(
            &PathBuf::from(CONSENSUS_CONFIG).with_extension(JSON_EXT),
            &serde_json::to_vec(&self.cfg.consensus).expect("Error encoding consensus config"),
        );

        // Note that the encrypted config returned here uses a different salt than the
        // on-disk version. While this may be confusing it shouldn't be a problem since
        // the content and encryption key are the same. It's unpractical to read the
        // on-disk version here since the server/api aren't aware of the config dir and
        // ideally we can keep it that way.
        let encryption_salt = random_salt();
        append(&PathBuf::from(SALT_FILE), encryption_salt.as_bytes());

        let private_config_bytes =
            serde_json::to_vec(&self.cfg.private).expect("Error encoding private config");
        let encryption_key = get_encryption_key(&password, &encryption_salt)
            .expect("Generating key from password failed");
        let private_config_encrypted =
            hex::encode(encrypt(private_config_bytes, &encryption_key).expect("Encryption failed"));
        append(
            &PathBuf::from(PRIVATE_CONFIG).with_extension(ENCRYPTED_EXT),
            private_config_encrypted.as_bytes(),
        );

        let tar_archive_bytes = tar_archive_builder
            .into_inner()
            .expect("Error building tar archive");

        Ok(GuardianConfigBackup { tar_archive_bytes })
    }

    async fn handle_backup_request<'s, 'dbtx, 'a>(
        &'s self,
        dbtx: &'dbtx mut DatabaseTransaction<'a>,
        request: SignedBackupRequest,
    ) -> Result<(), ApiError> {
        let request = request
            .verify_valid(SECP256K1)
            .map_err(|_| ApiError::bad_request("invalid request".into()))?;

        if request.payload.len() > BACKUP_REQUEST_MAX_PAYLOAD_SIZE_BYTES {
            return Err(ApiError::bad_request("snapshot too large".into()));
        }
        debug!(target: LOG_NET_API, id = %request.id, len = request.payload.len(), "Received client backup request");
        if let Some(prev) = dbtx.get_value(&ClientBackupKey(request.id)).await {
            if request.timestamp <= prev.timestamp {
                debug!(id = %request.id, len = request.payload.len(), "Received client backup request with old timestamp - ignoring");
                return Err(ApiError::bad_request("timestamp too small".into()));
            }
        }

        info!(target: LOG_NET_API, id = %request.id, len = request.payload.len(), "Storing new client backup");
        let overwritten = dbtx
            .insert_entry(
                &ClientBackupKey(request.id),
                &ClientBackupSnapshot {
                    timestamp: request.timestamp,
                    data: request.payload.to_vec(),
                },
            )
            .await
            .is_some();
        BACKUP_WRITE_SIZE_BYTES.observe(request.payload.len() as f64);
        if !overwritten {
            dbtx.on_commit(|| STORED_BACKUPS_COUNT.inc());
        }

        Ok(())
    }

    async fn handle_recover_request(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        id: secp256k1_zkp::PublicKey,
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
            db = self.db.with_prefix_module_id(id);
            dbtx = dbtx.with_prefix_module_id(id)
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
            VERSION_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> SupportedApiVersionsSummary {
                Ok(fedimint.api_versions_summary().to_owned())
            }
        },
        api_endpoint! {
            SUBMIT_TRANSACTION_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, transaction: SerdeTransaction| -> SerdeModuleEncoding<Result<TransactionId, TransactionError>> {
                let transaction = transaction
                    .try_into_inner(&fedimint.modules.decoder_registry())
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;

                // we return an inner error if and only if the submitted transaction is
                // invalid and will be rejected if we were to submit it to consensus
                Ok((&fedimint.submit_transaction(transaction).await).into())
            }
        },
        api_endpoint! {
            AWAIT_TRANSACTION_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, tx_hash: TransactionId| -> TransactionId {
                debug!(transaction = %tx_hash, "Received request");

                fedimint.await_transaction(tx_hash).await;

                debug!(transaction = %tx_hash, "Sending outcome");

                Ok(tx_hash)
            }
        },
        api_endpoint! {
            AWAIT_OUTPUT_OUTCOME_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, outpoint: OutPoint| -> SerdeModuleEncoding<DynOutputOutcome> {
                let outcome = fedimint
                    .await_output_outcome(outpoint)
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;

                Ok(outcome)
            }
        },
        api_endpoint! {
            INVITE_CODE_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context,  _v: ()| -> String {
                Ok(fedimint.cfg.get_invite_code().to_string())
            }
        },
        api_endpoint! {
            FEDERATION_ID_ENDPOINT,
            ApiVersion::new(0, 2),
            async |fedimint: &ConsensusApi, _context,  _v: ()| -> String {
                Ok(fedimint.cfg.get_federation_id().to_string())
            }
        },
        api_endpoint! {
            CLIENT_CONFIG_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> ClientConfig {
                Ok(fedimint.client_cfg.clone())
            }
        },
        api_endpoint! {
            SERVER_CONFIG_CONSENSUS_HASH_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> sha256::Hash {
                Ok(fedimint.cfg.consensus.consensus_hash())
            }
        },
        api_endpoint! {
            STATUS_ENDPOINT,
            ApiVersion::new(0, 0),
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
            SESSION_COUNT_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> u64 {
                Ok(fedimint.session_count().await)
            }
        },
        api_endpoint! {
            AWAIT_SESSION_OUTCOME_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, index: u64| -> SerdeModuleEncoding<SessionOutcome> {
                Ok((&fedimint.await_signed_session_outcome(index).await.session_outcome).into())
            }
        },
        api_endpoint! {
            AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, index: u64| -> SerdeModuleEncoding<SignedSessionOutcome> {
                Ok((&fedimint.await_signed_session_outcome(index).await).into())
            }
        },
        api_endpoint! {
            SESSION_STATUS_ENDPOINT,
            ApiVersion::new(0, 1),
            async |fedimint: &ConsensusApi, _context, index: u64| -> SerdeModuleEncoding<SessionStatus> {
                Ok((&fedimint.session_status(index).await).into())
            }
        },
        api_endpoint! {
            AUDIT_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, context, _v: ()| -> AuditSummary {
                check_auth(context)?;
                Ok(fedimint.get_federation_audit().await?)
            }
        },
        api_endpoint! {
            GUARDIAN_CONFIG_BACKUP_ENDPOINT,
            ApiVersion::new(0, 2),
            async |fedimint: &ConsensusApi, context, _v: ()| -> GuardianConfigBackup {
                check_auth(context)?;
                let password = context.request_auth().expect("Auth was checked before").0;
                Ok(fedimint.get_guardian_config_backup(password).await?)
            }
        },
        api_endpoint! {
            VERIFY_CONFIG_HASH_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, context, _v: ()| -> BTreeMap<PeerId, sha256::Hash> {
                check_auth(context)?;
                Ok(get_verification_hashes(&fedimint.cfg))
            }
        },
        api_endpoint! {
            BACKUP_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, context, request: SignedBackupRequest| -> () {
                fedimint
                    .handle_backup_request(&mut context.dbtx().into_nc(), request).await?;
                Ok(())

            }
        },
        api_endpoint! {
            RECOVER_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, context, id: secp256k1_zkp::PublicKey| -> Option<ClientBackupSnapshot> {
                Ok(fedimint
                    .handle_recover_request(&mut context.dbtx().into_nc(), id).await)
            }
        },
        api_endpoint! {
            AUTH_ENDPOINT,
            ApiVersion::new(0, 0),
            async |_fedimint: &ConsensusApi, context, _v: ()| -> () {
                check_auth(context)?;
                Ok(())
            }
        },
        api_endpoint! {
            MODULES_CONFIG_JSON_ENDPOINT,
            ApiVersion::new(0, 0),
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
