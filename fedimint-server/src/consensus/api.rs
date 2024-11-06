//! Implements the client API through which users interact with the federation
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bitcoin::hashes::sha256;
use fedimint_aead::{encrypt, get_encryption_key, random_salt};
use fedimint_api_client::api::{
    FederationStatus, GuardianConfigBackup, PeerConnectionStatus, PeerStatus, StatusResponse,
};
use fedimint_core::admin_client::ServerStatus;
use fedimint_core::backup::{ClientBackupKey, ClientBackupSnapshot};
use fedimint_core::bitcoin_migration::bitcoin30_to_bitcoin32_secp256k1_secret_key;
use fedimint_core::config::{ClientConfig, JsonClientConfig};
use fedimint_core::core::backup::{SignedBackupRequest, BACKUP_REQUEST_MAX_PAYLOAD_SIZE_BYTES};
use fedimint_core::core::{DynOutputOutcome, ModuleInstanceId};
use fedimint_core::db::{
    Committable, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::endpoint_constants::{
    API_ANNOUNCEMENTS_ENDPOINT, AUDIT_ENDPOINT, AUTH_ENDPOINT, AWAIT_OUTPUT_OUTCOME_ENDPOINT,
    AWAIT_SESSION_OUTCOME_ENDPOINT, AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT,
    AWAIT_TRANSACTION_ENDPOINT, BACKUP_ENDPOINT, CLIENT_CONFIG_ENDPOINT,
    CLIENT_CONFIG_JSON_ENDPOINT, FEDERATION_ID_ENDPOINT, FEDIMINTD_VERSION_ENDPOINT,
    GUARDIAN_CONFIG_BACKUP_ENDPOINT, INVITE_CODE_ENDPOINT, RECOVER_ENDPOINT,
    SERVER_CONFIG_CONSENSUS_HASH_ENDPOINT, SESSION_COUNT_ENDPOINT, SESSION_STATUS_ENDPOINT,
    SHUTDOWN_ENDPOINT, SIGN_API_ANNOUNCEMENT_ENDPOINT, STATUS_ENDPOINT,
    SUBMIT_API_ANNOUNCEMENT_ENDPOINT, SUBMIT_TRANSACTION_ENDPOINT, VERSION_ENDPOINT,
};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::audit::{Audit, AuditSummary};
use fedimint_core::module::registry::ServerModuleRegistry;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased, ApiVersion,
    SerdeModuleEncoding, SupportedApiVersionsSummary,
};
use fedimint_core::net::api_announcement::{
    ApiAnnouncement, SignedApiAnnouncement, SignedApiAnnouncementSubmission,
};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::secp256k1_27::SECP256K1;
use fedimint_core::server::DynServerModule;
use fedimint_core::session_outcome::{SessionOutcome, SessionStatus, SignedSessionOutcome};
use fedimint_core::transaction::{
    SerdeTransaction, Transaction, TransactionError, TransactionSubmissionOutcome,
};
use fedimint_core::util::SafeUrl;
use fedimint_core::{secp256k1, OutPoint, PeerId, TransactionId};
use fedimint_logging::LOG_NET_API;
use futures::StreamExt;
use tokio::sync::{watch, RwLock};
use tracing::{debug, info};

use crate::config::io::{
    CONSENSUS_CONFIG, ENCRYPTED_EXT, JSON_EXT, LOCAL_CONFIG, PRIVATE_CONFIG, SALT_FILE,
};
use crate::config::ServerConfig;
use crate::consensus::db::{AcceptedItemPrefix, AcceptedTransactionKey, SignedSessionOutcomeKey};
use crate::consensus::engine::get_finished_session_count_static;
use crate::consensus::transaction::process_transaction_with_dbtx;
use crate::fedimint_core::encoding::Encodable;
use crate::metrics::{BACKUP_WRITE_SIZE_BYTES, STORED_BACKUPS_COUNT};
use crate::net::api::announcement::{ApiAnnouncementKey, ApiAnnouncementPrefix};
use crate::net::api::{check_auth, ApiResult, GuardianAuthToken, HasApiContext};

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

    pub force_api_secret: Option<String>,
    /// For sending API events to consensus such as transactions
    pub submission_sender: async_channel::Sender<ConsensusItem>,
    pub shutdown_receiver: watch::Receiver<Option<u64>>,
    pub shutdown_sender: watch::Sender<Option<u64>>,
    pub connection_status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
    pub last_ci_by_peer: Arc<RwLock<BTreeMap<PeerId, u64>>>,
    pub supported_api_versions: SupportedApiVersionsSummary,
    pub code_version_str: String,
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

        process_transaction_with_dbtx(self.modules.clone(), &mut dbtx, &transaction).await?;

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
                &mut dbtx.to_ref_with_prefix_module_id(module_id).0.into_nc(),
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
        let peers_connection_status = self.connection_status_channels.read().await.clone();
        let last_ci_by_peer = self.last_ci_by_peer.read().await.clone();
        let session_count = self.session_count().await;
        let scheduled_shutdown = self.shutdown_receiver.borrow().to_owned();

        let status_by_peer = peers_connection_status
            .into_iter()
            .map(|(peer, connection_status)| {
                let last_contribution = last_ci_by_peer.get(&peer).copied();
                let flagged = last_contribution.unwrap_or(0) + 1 < session_count;

                let consensus_status = PeerStatus {
                    last_contribution,
                    connection_status,
                    flagged,
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

    async fn get_federation_audit(&self, _auth: &GuardianAuthToken) -> ApiResult<AuditSummary> {
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

        let mut dbtx = self.db.begin_transaction().await;

        if let Some(existing_announcement) = dbtx.get_value(&ApiAnnouncementKey(peer_id)).await {
            // If the current announcement is semantically identical to the new one (except
            // for potentially having a different, valid signature) we return ok to allow
            // the caller to stop submitting the value if they are in a retry loop.
            if existing_announcement.api_announcement == announcement.api_announcement {
                return Ok(());
            }

            // We only accept announcements with a nonce higher than the current one to
            // avoid replay attacks.
            if existing_announcement.api_announcement.nonce >= announcement.api_announcement.nonce {
                return Err(ApiError::bad_request(
                    "Outdated or redundant announcement".into(),
                ));
            }
        }

        dbtx.insert_entry(&ApiAnnouncementKey(peer_id), &announcement)
            .await;
        dbtx.commit_tx().await;
        Ok(())
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
                        let signed_announcement = announcement.sign(
                            &ctx,
                            &bitcoin30_to_bitcoin32_secp256k1_secret_key(
                                &self.cfg.private.broadcast_secret_key,
                            )
                            .keypair(&ctx),
                        );

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
            db = self.db.with_prefix_module_id(id).0;
            dbtx = dbtx.with_prefix_module_id(id).0;
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
                Ok(fedimint.cfg.consensus.consensus_hash())
            }
        },
        api_endpoint! {
            STATUS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> StatusResponse {
                Ok(StatusResponse {
                    server: ServerStatus::ConsensusRunning,
                    federation: Some(fedimint.get_federation_status().await?)
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
                let auth = check_auth(context)?;
                Ok(fedimint.get_federation_audit(&auth).await?)
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
                fedimint
                    .handle_backup_request(&mut context.dbtx().into_nc(), request).await?;
                Ok(())

            }
        },
        api_endpoint! {
            RECOVER_ENDPOINT,
            ApiVersion::new(0, 0),
            async |fedimint: &ConsensusApi, context, id: PublicKey| -> Option<ClientBackupSnapshot> {
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
            FEDIMINTD_VERSION_ENDPOINT,
            ApiVersion::new(0, 4),
            async |fedimint: &ConsensusApi, _context, _v: ()| -> String {
                Ok(fedimint.fedimintd_version())
            }
        },
    ]
}
