//! Implements the client API through which users interact with the federation
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bitcoin::hashes::sha256;
use fedimint_aead::{encrypt, get_encryption_key, random_salt};
use fedimint_api_client::api::{
    LegacyFederationStatus, LegacyP2PConnectionStatus, LegacyPeerStatus, StatusResponse,
};
use fedimint_core::admin_client::{GuardianConfigBackup, ServerStatusLegacy, SetupStatus};
use fedimint_core::backup::{
    BackupStatistics, ClientBackupKey, ClientBackupKeyPrefix, ClientBackupSnapshot,
};
use fedimint_core::config::{ClientConfig, JsonClientConfig, META_FEDERATION_NAME_KEY};
use fedimint_core::core::backup::{BACKUP_REQUEST_MAX_PAYLOAD_SIZE_BYTES, SignedBackupRequest};
use fedimint_core::core::{DynOutputOutcome, ModuleInstanceId, ModuleKind};
use fedimint_core::db::{
    Committable, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
};
#[allow(deprecated)]
use fedimint_core::endpoint_constants::AWAIT_OUTPUT_OUTCOME_ENDPOINT;
use fedimint_core::endpoint_constants::{
    API_ANNOUNCEMENTS_ENDPOINT, AUDIT_ENDPOINT, AUTH_ENDPOINT, AWAIT_OUTPUTS_OUTCOMES_ENDPOINT,
    AWAIT_SESSION_OUTCOME_ENDPOINT, AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT,
    AWAIT_TRANSACTION_ENDPOINT, BACKUP_ENDPOINT, BACKUP_STATISTICS_ENDPOINT, CHAIN_ID_ENDPOINT,
    CHANGE_PASSWORD_ENDPOINT, CLIENT_CONFIG_ENDPOINT, CLIENT_CONFIG_JSON_ENDPOINT,
    CONSENSUS_ORD_LATENCY_ENDPOINT, FEDERATION_ID_ENDPOINT, FEDIMINTD_VERSION_ENDPOINT,
    GUARDIAN_CONFIG_BACKUP_ENDPOINT, GUARDIAN_METADATA_ENDPOINT, INVITE_CODE_ENDPOINT,
    P2P_CONNECTION_STATUS_ENDPOINT, RECOVER_ENDPOINT, SERVER_CONFIG_CONSENSUS_HASH_ENDPOINT,
    SESSION_COUNT_ENDPOINT, SESSION_STATUS_ENDPOINT, SESSION_STATUS_V2_ENDPOINT,
    SETUP_STATUS_ENDPOINT, SHUTDOWN_ENDPOINT, SIGN_API_ANNOUNCEMENT_ENDPOINT,
    SIGN_GUARDIAN_METADATA_ENDPOINT, STATUS_ENDPOINT, SUBMIT_API_ANNOUNCEMENT_ENDPOINT,
    SUBMIT_GUARDIAN_METADATA_ENDPOINT, SUBMIT_TRANSACTION_ENDPOINT, VERSION_ENDPOINT,
};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::audit::{Audit, AuditSummary};
use fedimint_core::module::{
    ApiAuth, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased, ApiResult, ApiVersion,
    SerdeModuleEncoding, SerdeModuleEncodingBase64, SupportedApiVersionsSummary, api_endpoint,
};
use fedimint_core::net::api_announcement::{
    ApiAnnouncement, SignedApiAnnouncement, SignedApiAnnouncementSubmission,
};
use fedimint_core::net::auth::{GuardianAuthToken, check_auth};
use fedimint_core::secp256k1::{PublicKey, SECP256K1};
use fedimint_core::session_outcome::{
    SessionOutcome, SessionStatus, SessionStatusV2, SignedSessionOutcome,
};
use fedimint_core::task::TaskGroup;
use fedimint_core::transaction::{
    SerdeTransaction, Transaction, TransactionError, TransactionSubmissionOutcome,
};
use fedimint_core::util::{FmtCompact, SafeUrl};
use fedimint_core::{ChainId, OutPoint, OutPointRange, PeerId, TransactionId, secp256k1};
use fedimint_logging::LOG_NET_API;
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_server_core::dashboard_ui::{
    IDashboardApi, P2PConnectionStatus, ServerBitcoinRpcStatus,
};
use fedimint_server_core::{DynServerModule, ServerModuleRegistry, ServerModuleRegistryExt};
use futures::StreamExt;
use tokio::sync::watch::{self, Receiver, Sender};
use tracing::{debug, info, warn};

use crate::config::io::{
    CONSENSUS_CONFIG, ENCRYPTED_EXT, JSON_EXT, LOCAL_CONFIG, PRIVATE_CONFIG, SALT_FILE,
    reencrypt_private_config,
};
use crate::config::{ServerConfig, legacy_consensus_config_hash};
use crate::consensus::db::{AcceptedItemPrefix, AcceptedTransactionKey, SignedSessionOutcomeKey};
use crate::consensus::engine::get_finished_session_count_static;
use crate::consensus::transaction::{TxProcessingMode, process_transaction_with_dbtx};
use crate::metrics::{BACKUP_WRITE_SIZE_BYTES, STORED_BACKUPS_COUNT};
use crate::net::api::HasApiContext;
use crate::net::api::announcement::{ApiAnnouncementKey, ApiAnnouncementPrefix};
use crate::net::p2p::P2PStatusReceivers;

#[derive(Clone)]
pub struct ConsensusApi {
    /// Our server configuration
    pub cfg: ServerConfig,
    /// Directory where config files are stored
    pub cfg_dir: PathBuf,
    /// Database for serving the API
    pub db: Database,
    /// Modules registered with the federation
    pub modules: ServerModuleRegistry,
    /// Cached client config
    pub client_cfg: ClientConfig,
    pub force_api_secret: Option<String>,
    /// For sending API events to consensus such as transactions
    pub submission_sender: async_channel::Sender<ConsensusItem>,
    pub shutdown_receiver: Receiver<Option<u64>>,
    pub shutdown_sender: Sender<Option<u64>>,
    pub ord_latency_receiver: watch::Receiver<Option<Duration>>,
    pub p2p_status_receivers: P2PStatusReceivers,
    pub ci_status_receivers: BTreeMap<PeerId, Receiver<Option<u64>>>,
    pub bitcoin_rpc_connection: ServerBitcoinRpcMonitor,
    pub supported_api_versions: SupportedApiVersionsSummary,
    pub code_version_str: String,
    pub task_group: TaskGroup,
}

impl ConsensusApi {
    pub fn api_versions_summary(&self) -> &SupportedApiVersionsSummary {
        &self.supported_api_versions
    }

    pub fn get_active_api_secret(&self) -> Option<String> {
        // TODO: In the future, we might want to fetch it from the DB, so it's possible
        // to customize from the UX
        self.force_api_secret.clone()
    }

    // we want to return an error if and only if the submitted transaction is
    // invalid and will be rejected if we were to submit it to consensus
    pub async fn submit_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<TransactionId, TransactionError> {
        let txid = transaction.tx_hash();

        debug!(target: LOG_NET_API, %txid, "Received a submitted transaction");

        // Create read-only DB tx so that the read state is consistent
        let mut dbtx = self.db.begin_transaction_nc().await;
        // we already processed the transaction before
        if dbtx
            .get_value(&AcceptedTransactionKey(txid))
            .await
            .is_some()
        {
            debug!(target: LOG_NET_API, %txid, "Transaction already accepted");
            return Ok(txid);
        }

        // We ignore any writes, as we only verify if the transaction is valid here
        dbtx.ignore_uncommitted();

        process_transaction_with_dbtx(
            self.modules.clone(),
            &mut dbtx,
            &transaction,
            self.cfg.consensus.version,
            TxProcessingMode::Submission,
        )
        .await
        .inspect_err(|err| {
            debug!(target: LOG_NET_API, %txid, err = %err.fmt_compact(), "Transaction rejected");
        })?;

        let _ = self
            .submission_sender
            .send(ConsensusItem::Transaction(transaction.clone()))
            .await
            .inspect_err(|err| {
                warn!(target: LOG_NET_API, %txid, err = %err.fmt_compact(), "Unable to submit the tx into consensus");
            });

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
            .with_context(|| format!("Outpoint index out of bounds {outpoint:?}"))?;

        #[allow(deprecated)]
        let outcome = self
            .modules
            .get_expect(module_id)
            .output_status(
                &mut dbtx.to_ref_with_prefix_module_id(module_id).0.into_nc(),
                outpoint,
                module_id,
            )
            .await
            .context("No output outcome for outpoint")?;

        Ok((&outcome).into())
    }

    pub async fn await_outputs_outcomes(
        &self,
        outpoint_range: OutPointRange,
    ) -> Result<Vec<Option<SerdeModuleEncoding<DynOutputOutcome>>>> {
        // Wait for the transaction to be accepted first
        let (module_ids, mut dbtx) = self.await_transaction(outpoint_range.txid()).await;

        let mut outcomes = Vec::with_capacity(outpoint_range.count());

        for outpoint in outpoint_range {
            let module_id = module_ids
                .get(outpoint.out_idx as usize)
                .with_context(|| format!("Outpoint index out of bounds {outpoint:?}"))?;

            #[allow(deprecated)]
            let outcome = self
                .modules
                .get_expect(*module_id)
                .output_status(
                    &mut dbtx.to_ref_with_prefix_module_id(*module_id).0.into_nc(),
                    outpoint,
                    *module_id,
                )
                .await
                .map(|outcome| (&outcome).into());

            outcomes.push(outcome);
        }

        Ok(outcomes)
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

    pub async fn session_status(&self, session_index: u64) -> SessionStatusV2 {
        let mut dbtx = self.db.begin_transaction_nc().await;

        match session_index.cmp(&get_finished_session_count_static(&mut dbtx).await) {
            Ordering::Greater => SessionStatusV2::Initial,
            Ordering::Equal => SessionStatusV2::Pending(
                dbtx.find_by_prefix(&AcceptedItemPrefix)
                    .await
                    .map(|entry| entry.1)
                    .collect()
                    .await,
            ),
            Ordering::Less => SessionStatusV2::Complete(
                dbtx.get_value(&SignedSessionOutcomeKey(session_index))
                    .await
                    .expect("There are no gaps in session outcomes"),
            ),
        }
    }

    pub async fn get_federation_status(&self) -> ApiResult<LegacyFederationStatus> {
        let session_count = self.session_count().await;
        let scheduled_shutdown = self.shutdown_receiver.borrow().to_owned();

        let status_by_peer = self
            .p2p_status_receivers
            .iter()
            .map(|(peer, p2p_receiver)| {
                let ci_receiver = self.ci_status_receivers.get(peer).unwrap();

                let consensus_status = LegacyPeerStatus {
                    connection_status: match *p2p_receiver.borrow() {
                        Some(..) => LegacyP2PConnectionStatus::Connected,
                        None => LegacyP2PConnectionStatus::Disconnected,
                    },
                    last_contribution: *ci_receiver.borrow(),
                    flagged: ci_receiver.borrow().unwrap_or(0) + 1 < session_count,
                };

                (*peer, consensus_status)
            })
            .collect::<HashMap<PeerId, LegacyPeerStatus>>();

        let peers_flagged = status_by_peer
            .values()
            .filter(|status| status.flagged)
            .count() as u64;

        let peers_online = status_by_peer
            .values()
            .filter(|status| status.connection_status == LegacyP2PConnectionStatus::Connected)
            .count() as u64;

        let peers_offline = status_by_peer
            .values()
            .filter(|status| status.connection_status == LegacyP2PConnectionStatus::Disconnected)
            .count() as u64;

        Ok(LegacyFederationStatus {
            session_count,
            status_by_peer,
            peers_online,
            peers_offline,
            peers_flagged,
            scheduled_shutdown,
        })
    }

    fn shutdown(&self, index: Option<u64>) {
        self.shutdown_sender.send_replace(index);
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
                    &mut dbtx.to_ref_with_prefix_module_id(module_instance_id).0,
                    &mut audit,
                    module_instance_id,
                )
                .await;
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
    fn get_guardian_config_backup(
        &self,
        password: &str,
        _auth: &GuardianAuthToken,
    ) -> GuardianConfigBackup {
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
        let encryption_key = get_encryption_key(password, &encryption_salt)
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

        GuardianConfigBackup { tar_archive_bytes }
    }

    async fn handle_backup_request(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        request: SignedBackupRequest,
    ) -> Result<(), ApiError> {
        let request = request
            .verify_valid(SECP256K1)
            .map_err(|_| ApiError::bad_request("invalid request".into()))?;

        if request.payload.len() > BACKUP_REQUEST_MAX_PAYLOAD_SIZE_BYTES {
            return Err(ApiError::bad_request("snapshot too large".into()));
        }
        debug!(target: LOG_NET_API, id = %request.id, len = request.payload.len(), "Received client backup request");
        if let Some(prev) = dbtx.get_value(&ClientBackupKey(request.id)).await
            && request.timestamp <= prev.timestamp
        {
            debug!(target: LOG_NET_API, id = %request.id, len = request.payload.len(), "Received client backup request with old timestamp - ignoring");
            return Err(ApiError::bad_request("timestamp too small".into()));
        }

        info!(target: LOG_NET_API, id = %request.id, len = request.payload.len(), "Storing new client backup");
        let overwritten = dbtx
            .insert_entry(
                &ClientBackupKey(request.id),
                &ClientBackupSnapshot {
                    timestamp: request.timestamp,
                    data: request.payload.clone(),
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
        id: PublicKey,
    ) -> Option<ClientBackupSnapshot> {
        dbtx.get_value(&ClientBackupKey(id)).await
    }

    /// List API URL announcements from all peers we have received them from (at
    /// least ourselves)
    async fn api_announcements(&self) -> BTreeMap<PeerId, SignedApiAnnouncement> {
        self.db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&ApiAnnouncementPrefix)
            .await
            .map(|(announcement_key, announcement)| (announcement_key.0, announcement))
            .collect()
            .await
    }

    /// Returns the tagged fedimintd version currently running
    fn fedimintd_version(&self) -> String {
        self.code_version_str.clone()
    }

    /// Add an API URL announcement from a peer to our database to be returned
    /// by [`ConsensusApi::api_announcements`].
    async fn submit_api_announcement(
        &self,
        peer_id: PeerId,
        announcement: SignedApiAnnouncement,
    ) -> Result<(), ApiError> {
        let Some(peer_key) = self.cfg.consensus.broadcast_public_keys.get(&peer_id) else {
            return Err(ApiError::bad_request("Peer not in federation".into()));
        };

        if !announcement.verify(SECP256K1, peer_key) {
            return Err(ApiError::bad_request("Invalid signature".into()));
        }

        // Use autocommit to handle potential transaction conflicts with retries
        self.db
            .autocommit(
                |dbtx, _| {
                    let announcement = announcement.clone();
                    Box::pin(async move {
                        if let Some(existing_announcement) =
                            dbtx.get_value(&ApiAnnouncementKey(peer_id)).await
                        {
                            // If the current announcement is semantically identical to the new one
                            // (except for potentially having a
                            // different, valid signature) we return ok to allow
                            // the caller to stop submitting the value if they are in a retry loop.
                            if existing_announcement.api_announcement
                                == announcement.api_announcement
                            {
                                return Ok(());
                            }

                            // We only accept announcements with a nonce higher than the current one
                            // to avoid replay attacks.
                            if existing_announcement.api_announcement.nonce
                                >= announcement.api_announcement.nonce
                            {
                                return Err(ApiError::bad_request(
                                    "Outdated or redundant announcement".into(),
                                ));
                            }
                        }

                        dbtx.insert_entry(&ApiAnnouncementKey(peer_id), &announcement)
                            .await;
                        Ok(())
                    })
                },
                None,
            )
            .await
            .map_err(|e| match e {
                fedimint_core::db::AutocommitError::ClosureError { error, .. } => error,
                fedimint_core::db::AutocommitError::CommitFailed { last_error, .. } => {
                    ApiError::server_error(format!("Database commit failed: {last_error}"))
                }
            })
    }

    async fn sign_api_announcement(&self, new_url: SafeUrl) -> SignedApiAnnouncement {
        self.db
            .autocommit(
                |dbtx, _| {
                    let new_url_inner = new_url.clone();
                    Box::pin(async move {
                        let new_nonce = dbtx
                            .get_value(&ApiAnnouncementKey(self.cfg.local.identity))
                            .await
                            .map_or(0, |a| a.api_announcement.nonce + 1);
                        let announcement = ApiAnnouncement {
                            api_url: new_url_inner,
                            nonce: new_nonce,
                        };
                        let ctx = secp256k1::Secp256k1::new();
                        let signed_announcement = announcement
                            .sign(&ctx, &self.cfg.private.broadcast_secret_key.keypair(&ctx));

                        dbtx.insert_entry(
                            &ApiAnnouncementKey(self.cfg.local.identity),
                            &signed_announcement,
                        )
                        .await;

                        Result::<_, ()>::Ok(signed_announcement)
                    })
                },
                None,
            )
            .await
            .expect("Will not terminate on error")
    }

    async fn guardian_metadata_list(
        &self,
    ) -> BTreeMap<PeerId, fedimint_core::net::guardian_metadata::SignedGuardianMetadata> {
        use crate::net::api::guardian_metadata::{GuardianMetadataKey, GuardianMetadataPrefix};

        self.db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&GuardianMetadataPrefix)
            .await
            .map(|(key, metadata): (GuardianMetadataKey, _)| (key.0, metadata))
            .collect()
            .await
    }

    async fn submit_guardian_metadata(
        &self,
        peer_id: PeerId,
        metadata: fedimint_core::net::guardian_metadata::SignedGuardianMetadata,
    ) -> Result<(), ApiError> {
        use crate::net::api::guardian_metadata::GuardianMetadataKey;

        let Some(peer_key) = self.cfg.consensus.broadcast_public_keys.get(&peer_id) else {
            return Err(ApiError::bad_request("Peer not in federation".into()));
        };

        let now = fedimint_core::time::duration_since_epoch();
        if let Err(e) = metadata.verify(SECP256K1, peer_key, now) {
            return Err(ApiError::bad_request(format!(
                "Invalid signature or timestamp: {e}"
            )));
        }

        let mut dbtx = self.db.begin_transaction().await;

        if let Some(existing_metadata) = dbtx.get_value(&GuardianMetadataKey(peer_id)).await {
            // If the current metadata is semantically identical to the new one (except
            // for potentially having a different, valid signature) we return ok to allow
            // the caller to stop submitting the value if they are in a retry loop.
            if existing_metadata.bytes == metadata.bytes {
                return Ok(());
            }

            // Only update if the new metadata has a newer timestamp
            if metadata.guardian_metadata().timestamp_secs
                <= existing_metadata.guardian_metadata().timestamp_secs
            {
                return Err(ApiError::bad_request(
                    "New metadata timestamp is not newer than existing".into(),
                ));
            }
        }

        dbtx.insert_entry(&GuardianMetadataKey(peer_id), &metadata)
            .await;
        dbtx.commit_tx().await;

        Ok(())
    }

    async fn sign_guardian_metadata(
        &self,
        new_metadata: fedimint_core::net::guardian_metadata::GuardianMetadata,
    ) -> fedimint_core::net::guardian_metadata::SignedGuardianMetadata {
        use crate::net::api::guardian_metadata::GuardianMetadataKey;

        let ctx = secp256k1::Secp256k1::new();
        let signed_metadata =
            new_metadata.sign(&ctx, &self.cfg.private.broadcast_secret_key.keypair(&ctx));

        self.db
            .autocommit(
                |dbtx, _| {
                    let signed_metadata_inner = signed_metadata.clone();
                    Box::pin(async move {
                        dbtx.insert_entry(
                            &GuardianMetadataKey(self.cfg.local.identity),
                            &signed_metadata_inner,
                        )
                        .await;

                        Result::<_, ()>::Ok(signed_metadata_inner)
                    })
                },
                None,
            )
            .await
            .expect("Will not terminate on error")
    }

    /// Changes the guardian password by re-encrypting the private config and
    /// changing the on-disk password file if present. `fedimintd` is shut down
    /// afterward, the user's service manager (e.g. `systemd` is expected to
    /// restart it).
    fn change_guardian_password(
        &self,
        new_password: &str,
        _auth: &GuardianAuthToken,
    ) -> Result<(), ApiError> {
        reencrypt_private_config(&self.cfg_dir, &self.cfg.private, new_password)
            .map_err(|e| ApiError::server_error(format!("Failed to change password: {e}")))?;

        info!(target: LOG_NET_API, "Successfully changed guardian password");

        Ok(())
    }
}

#[async_trait]
impl HasApiContext<ConsensusApi> for ConsensusApi {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&ConsensusApi, ApiEndpointContext) {
        let mut db = self.db.clone();
        if let Some(id) = id {
            db = self.db.with_prefix_module_id(id).0;
        }
        (
            self,
            ApiEndpointContext::new(
                db,
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
    ) -> (&DynServerModule, ApiEndpointContext) {
        let (_, context): (&ConsensusApi, _) = self.context(request, id).await;
        (
            self.modules.get_expect(id.expect("required module id")),
            context,
        )
    }
}

#[async_trait]
impl IDashboardApi for ConsensusApi {
    async fn auth(&self) -> ApiAuth {
        self.cfg.private.api_auth.clone()
    }

    async fn guardian_id(&self) -> PeerId {
        self.cfg.local.identity
    }

    async fn guardian_names(&self) -> BTreeMap<PeerId, String> {
        self.cfg
            .consensus
            .api_endpoints()
            .iter()
            .map(|(peer_id, endpoint)| (*peer_id, endpoint.name.clone()))
            .collect()
    }

    async fn federation_name(&self) -> String {
        self.cfg
            .consensus
            .meta
            .get(META_FEDERATION_NAME_KEY)
            .cloned()
            .expect("Federation name must be set")
    }

    async fn session_count(&self) -> u64 {
        self.session_count().await
    }

    async fn get_session_status(&self, session_idx: u64) -> SessionStatusV2 {
        self.session_status(session_idx).await
    }

    async fn consensus_ord_latency(&self) -> Option<Duration> {
        *self.ord_latency_receiver.borrow()
    }

    async fn p2p_connection_status(&self) -> BTreeMap<PeerId, Option<P2PConnectionStatus>> {
        self.p2p_status_receivers
            .iter()
            .map(|(peer, receiver)| (*peer, receiver.borrow().clone()))
            .collect()
    }

    async fn federation_invite_code(&self) -> String {
        self.cfg
            .get_invite_code(self.get_active_api_secret())
            .to_string()
    }

    async fn federation_audit(&self) -> AuditSummary {
        self.get_federation_audit()
            .await
            .expect("Failed to get federation audit")
    }

    async fn bitcoin_rpc_url(&self) -> SafeUrl {
        self.bitcoin_rpc_connection.url()
    }

    async fn bitcoin_rpc_status(&self) -> Option<ServerBitcoinRpcStatus> {
        self.bitcoin_rpc_connection.status()
    }

    async fn download_guardian_config_backup(
        &self,
        password: &str,
        guardian_auth: &GuardianAuthToken,
    ) -> GuardianConfigBackup {
        self.get_guardian_config_backup(password, guardian_auth)
    }

    fn get_module_by_kind(&self, kind: ModuleKind) -> Option<&DynServerModule> {
        self.modules
            .iter_modules()
            .find_map(|(_, module_kind, module)| {
                if *module_kind == kind {
                    Some(module)
                } else {
                    None
                }
            })
    }

    async fn fedimintd_version(&self) -> String {
        self.code_version_str.clone()
    }

    async fn change_password(
        &self,
        new_password: &str,
        current_password: &str,
        guardian_auth: &GuardianAuthToken,
    ) -> Result<(), String> {
        let auth = &self.auth().await.0;
        if auth != current_password {
            return Err("Current password is incorrect".into());
        }
        self.change_guardian_password(new_password, guardian_auth)
            .map_err(|e| e.to_string())
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
            async |fedimint: &ConsensusApi, _context, transaction: SerdeTransaction| -> SerdeModuleEncoding<TransactionSubmissionOutcome> {
                let transaction = transaction
                    .try_into_inner(&fedimint.modules.decoder_registry())
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;

                // we return an inner error if and only if the submitted transaction is
                // invalid and will be rejected if we were to submit it to consensus
                Ok((&TransactionSubmissionOutcome(fedimint.submit_transaction(transaction).await)).into())
            }
        },
        api_endpoint! {
            AWAIT_TRANSACTION_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, tx_hash: TransactionId| -> TransactionId {
                fedimint.await_transaction(tx_hash).await;

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
            AWAIT_OUTPUTS_OUTCOMES_ENDPOINT,
            ApiVersion::new(0, 8),
            async |fedimint: &ConsensusApi, _context, outpoint_range: OutPointRange| -> Vec<Option<SerdeModuleEncoding<DynOutputOutcome>>> {
                let outcomes = fedimint
                    .await_outputs_outcomes(outpoint_range)
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;

                Ok(outcomes)
            }
        },
        api_endpoint! {
            INVITE_CODE_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context,  _v: ()| -> String {
                Ok(fedimint.cfg.get_invite_code(fedimint.get_active_api_secret()).to_string())
            }
        },
        api_endpoint! {
            FEDERATION_ID_ENDPOINT,
            ApiVersion::new(0, 2),
            async |fedimint: &ConsensusApi, _context,  _v: ()| -> String {
                Ok(fedimint.cfg.calculate_federation_id().to_string())
            }
        },
        api_endpoint! {
            CLIENT_CONFIG_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> ClientConfig {
                Ok(fedimint.client_cfg.clone())
            }
        },
        // Helper endpoint for Admin UI that can't parse consensus encoding
        api_endpoint! {
            CLIENT_CONFIG_JSON_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> JsonClientConfig {
                Ok(fedimint.client_cfg.to_json())
            }
        },
        api_endpoint! {
            SERVER_CONFIG_CONSENSUS_HASH_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> sha256::Hash {
                Ok(legacy_consensus_config_hash(&fedimint.cfg.consensus))
            }
        },
        api_endpoint! {
            STATUS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> StatusResponse {
                Ok(StatusResponse {
                    server: ServerStatusLegacy::ConsensusRunning,
                    federation: Some(fedimint.get_federation_status().await?)
                })}
        },
        api_endpoint! {
            SETUP_STATUS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |_f: &ConsensusApi, _c, _v: ()| -> SetupStatus {
                Ok(SetupStatus::ConsensusIsRunning)
            }
        },
        api_endpoint! {
            CONSENSUS_ORD_LATENCY_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _c, _v: ()| -> Option<Duration> {
                Ok(*fedimint.ord_latency_receiver.borrow())
            }
        },
        api_endpoint! {
            P2P_CONNECTION_STATUS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _c, _v: ()| -> BTreeMap<PeerId, Option<P2PConnectionStatus>> {
                Ok(fedimint.p2p_status_receivers
                    .iter()
                    .map(|(peer, receiver)| (*peer, receiver.borrow().clone()))
                    .collect())
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
                Ok((&SessionStatus::from(fedimint.session_status(index).await)).into())
            }
        },
        api_endpoint! {
            SESSION_STATUS_V2_ENDPOINT,
            ApiVersion::new(0, 5),
            async |fedimint: &ConsensusApi, _context, index: u64| -> SerdeModuleEncodingBase64<SessionStatusV2> {
                Ok((&fedimint.session_status(index).await).into())
            }
        },
        api_endpoint! {
            SHUTDOWN_ENDPOINT,
            ApiVersion::new(0, 3),
            async |fedimint: &ConsensusApi, context, index: Option<u64>| -> () {
                check_auth(context)?;
                fedimint.shutdown(index);
                Ok(())
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
                let auth = check_auth(context)?;
                let password = context.request_auth().expect("Auth was checked before").0;
                Ok(fedimint.get_guardian_config_backup(&password, &auth))
            }
        },
        api_endpoint! {
            BACKUP_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, context, request: SignedBackupRequest| -> () {
                let db = context.db();
                let mut dbtx = db.begin_transaction().await;
                fedimint
                    .handle_backup_request(&mut dbtx.to_ref_nc(), request).await?;
                dbtx.commit_tx_result().await?;
                Ok(())

            }
        },
        api_endpoint! {
            RECOVER_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, context, id: PublicKey| -> Option<ClientBackupSnapshot> {
                let db = context.db();
                let mut dbtx = db.begin_transaction_nc().await;
                Ok(fedimint
                    .handle_recover_request(&mut dbtx, id).await)
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
            API_ANNOUNCEMENTS_ENDPOINT,
            ApiVersion::new(0, 3),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> BTreeMap<PeerId, SignedApiAnnouncement> {
                Ok(fedimint.api_announcements().await)
            }
        },
        api_endpoint! {
            SUBMIT_API_ANNOUNCEMENT_ENDPOINT,
            ApiVersion::new(0, 3),
            async |fedimint: &ConsensusApi, _context, submission: SignedApiAnnouncementSubmission| -> () {
                fedimint.submit_api_announcement(submission.peer_id, submission.signed_api_announcement).await
            }
        },
        api_endpoint! {
            SIGN_API_ANNOUNCEMENT_ENDPOINT,
            ApiVersion::new(0, 3),
            async |fedimint: &ConsensusApi, context, new_url: SafeUrl| -> SignedApiAnnouncement {
                check_auth(context)?;
                Ok(fedimint.sign_api_announcement(new_url).await)
            }
        },
        api_endpoint! {
            GUARDIAN_METADATA_ENDPOINT,
            ApiVersion::new(0, 9),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> BTreeMap<PeerId, fedimint_core::net::guardian_metadata::SignedGuardianMetadata> {
                Ok(fedimint.guardian_metadata_list().await)
            }
        },
        api_endpoint! {
            SUBMIT_GUARDIAN_METADATA_ENDPOINT,
            ApiVersion::new(0, 9),
            async |fedimint: &ConsensusApi, _context, submission: fedimint_core::net::guardian_metadata::SignedGuardianMetadataSubmission| -> () {
                fedimint.submit_guardian_metadata(submission.peer_id, submission.signed_guardian_metadata).await
            }
        },
        api_endpoint! {
            SIGN_GUARDIAN_METADATA_ENDPOINT,
            ApiVersion::new(0, 9),
            async |fedimint: &ConsensusApi, context, metadata: fedimint_core::net::guardian_metadata::GuardianMetadata| -> fedimint_core::net::guardian_metadata::SignedGuardianMetadata {
                check_auth(context)?;
                Ok(fedimint.sign_guardian_metadata(metadata).await)
            }
        },
        api_endpoint! {
            FEDIMINTD_VERSION_ENDPOINT,
            ApiVersion::new(0, 4),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> String {
                Ok(fedimint.fedimintd_version())
            }
        },
        api_endpoint! {
            BACKUP_STATISTICS_ENDPOINT,
            ApiVersion::new(0, 5),
            async |_fedimint: &ConsensusApi, context, _v: ()| -> BackupStatistics {
                check_auth(context)?;
                let db = context.db();
                let mut dbtx = db.begin_transaction_nc().await;
                Ok(backup_statistics_static(&mut dbtx).await)
            }
        },
        api_endpoint! {
            CHANGE_PASSWORD_ENDPOINT,
            ApiVersion::new(0, 6),
            async |fedimint: &ConsensusApi, context, new_password: String| -> () {
                let auth = check_auth(context)?;
                fedimint.change_guardian_password(&new_password, &auth)?;
                let task_group = fedimint.task_group.clone();
                fedimint_core::runtime::spawn("shutdown after password change",  async move {
                    info!(target: LOG_NET_API, "Will shutdown after password change");
                    fedimint_core:: runtime::sleep(Duration::from_secs(1)).await;
                    task_group.shutdown();
                });
                Ok(())
            }
        },
        api_endpoint! {
            CHAIN_ID_ENDPOINT,
            ApiVersion::new(0, 9),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> ChainId {
                fedimint
                    .bitcoin_rpc_connection
                    .get_chain_id()
                    .await
                    .map_err(|e| ApiError::server_error(e.to_string()))
            }
        },
    ]
}

pub(crate) async fn backup_statistics_static(
    dbtx: &mut DatabaseTransaction<'_>,
) -> BackupStatistics {
    const DAY_SECS: u64 = 24 * 60 * 60;
    const WEEK_SECS: u64 = 7 * DAY_SECS;
    const MONTH_SECS: u64 = 30 * DAY_SECS;
    const QUARTER_SECS: u64 = 3 * MONTH_SECS;

    let mut backup_stats = BackupStatistics::default();

    let mut all_backups_stream = dbtx.find_by_prefix(&ClientBackupKeyPrefix).await;
    while let Some((_, backup)) = all_backups_stream.next().await {
        backup_stats.num_backups += 1;
        backup_stats.total_size += backup.data.len();

        let age_secs = backup.timestamp.elapsed().unwrap_or_default().as_secs();
        if age_secs < DAY_SECS {
            backup_stats.refreshed_1d += 1;
        }
        if age_secs < WEEK_SECS {
            backup_stats.refreshed_1w += 1;
        }
        if age_secs < MONTH_SECS {
            backup_stats.refreshed_1m += 1;
        }
        if age_secs < QUARTER_SECS {
            backup_stats.refreshed_3m += 1;
        }
    }

    backup_stats
}
