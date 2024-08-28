use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::result;
use std::sync::Arc;

use anyhow::anyhow;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1;
use fedimint_core::admin_client::{
    ConfigGenConnectionsRequest, ConfigGenParamsRequest, ConfigGenParamsResponse, PeerServerParams,
};
use fedimint_core::backup::ClientBackupSnapshot;
use fedimint_core::core::backup::SignedBackupRequest;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::endpoint_constants::{
    ADD_CONFIG_GEN_PEER_ENDPOINT, API_ANNOUNCEMENTS_ENDPOINT, AUDIT_ENDPOINT, AUTH_ENDPOINT,
    AWAIT_SESSION_OUTCOME_ENDPOINT, AWAIT_TRANSACTION_ENDPOINT, BACKUP_ENDPOINT,
    CONFIG_GEN_PEERS_ENDPOINT, CONSENSUS_CONFIG_GEN_PARAMS_ENDPOINT,
    DEFAULT_CONFIG_GEN_PARAMS_ENDPOINT, GUARDIAN_CONFIG_BACKUP_ENDPOINT, RECOVER_ENDPOINT,
    RESTART_FEDERATION_SETUP_ENDPOINT, RUN_DKG_ENDPOINT, SERVER_CONFIG_CONSENSUS_HASH_ENDPOINT,
    SESSION_COUNT_ENDPOINT, SESSION_STATUS_ENDPOINT, SET_CONFIG_GEN_CONNECTIONS_ENDPOINT,
    SET_CONFIG_GEN_PARAMS_ENDPOINT, SET_PASSWORD_ENDPOINT, SHUTDOWN_ENDPOINT,
    SIGN_API_ANNOUNCEMENT_ENDPOINT, START_CONSENSUS_ENDPOINT, STATUS_ENDPOINT,
    SUBMIT_API_ANNOUNCEMENT_ENDPOINT, SUBMIT_TRANSACTION_ENDPOINT, VERIFIED_CONFIGS_ENDPOINT,
    VERIFY_CONFIG_HASH_ENDPOINT,
};
use fedimint_core::module::audit::AuditSummary;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiAuth, ApiRequestErased, SerdeModuleEncoding};
use fedimint_core::net::api_announcement::{
    SignedApiAnnouncement, SignedApiAnnouncementSubmission,
};
use fedimint_core::session_outcome::{AcceptedItem, SessionOutcome, SessionStatus};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::transaction::{SerdeTransaction, Transaction, TransactionSubmissionOutcome};
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, NumPeersExt, PeerId, TransactionId};
use fedimint_logging::{LOG_CLIENT, LOG_CLIENT_NET_API};
use futures::future::join_all;
use jsonrpsee_core::client::Error as JsonRpcClientError;
use serde_json::Value;
use tokio::sync::OnceCell;
use tracing::debug;

use super::{
    DynModuleApi, FederationApiExt, FederationError, FederationResult, GuardianConfigBackup,
    IGlobalFederationApi, IRawFederationApi, PeerResult, StatusResponse,
};
use crate::query::FilterMapThreshold;

/// [`IGlobalFederationApi`] wrapping some `T: IRawFederationApi` and adding
/// a tiny bit of caching.
#[derive(Debug)]
pub struct GlobalFederationApiWithCache<T> {
    inner: T,
    /// Small LRU used as [`IGlobalFederationApi::await_block`] cache.
    ///
    /// This is mostly to avoid multiple client module recovery processes
    /// re-requesting same blocks and putting burden on the federation.
    ///
    /// The LRU can be be fairly small, as if the modules are
    /// (near-)bottlenecked on fetching blocks they will naturally
    /// synchronize, or split into a handful of groups. And if they are not,
    /// no LRU here is going to help them.
    await_session_lru: Arc<tokio::sync::Mutex<lru::LruCache<u64, Arc<OnceCell<SessionOutcome>>>>>,

    /// Like [`Self::await_session_lru`], but for
    /// [`IGlobalFederationApi::get_session_status`].
    ///
    /// In theory these two LRUs have the same content, but one is locked by
    /// potentially long-blocking operation, while the other non-blocking one.
    /// Given how tiny they are, it's not worth complicating things to unify
    /// them.
    get_session_status_lru:
        Arc<tokio::sync::Mutex<lru::LruCache<u64, Arc<OnceCell<SessionOutcome>>>>>,
}

impl<T> GlobalFederationApiWithCache<T> {
    pub fn new(inner: T) -> GlobalFederationApiWithCache<T> {
        Self {
            inner,
            await_session_lru: Arc::new(tokio::sync::Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(512).expect("is non-zero"),
            ))),
            get_session_status_lru: Arc::new(tokio::sync::Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(512).expect("is non-zero"),
            ))),
        }
    }
}

impl<T> GlobalFederationApiWithCache<T>
where
    T: IRawFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn await_block_raw(
        &self,
        block_index: u64,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionOutcome> {
        debug!(target: LOG_CLIENT_NET_API, block_index, "Awaiting block's outcome from Federation");
        self.request_current_consensus::<SerdeModuleEncoding<SessionOutcome>>(
            AWAIT_SESSION_OUTCOME_ENDPOINT.to_string(),
            ApiRequestErased::new(block_index),
        )
        .await?
        .try_into_inner(decoders)
        .map_err(|e| anyhow!(e.to_string()))
    }

    async fn get_session_status_raw(
        &self,
        block_index: u64,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionStatus> {
        debug!(target: LOG_CLIENT_NET_API, block_index, "Fetching block's outcome from Federation");
        self.request_current_consensus::<SerdeModuleEncoding<SessionStatus>>(
            SESSION_STATUS_ENDPOINT.to_string(),
            ApiRequestErased::new(block_index),
        )
        .await?
        .try_into_inner(&decoders.clone().with_fallback())
        .map_err(|e| anyhow!(e))
    }
}

#[apply(async_trait_maybe_send!)]
impl<T> IRawFederationApi for GlobalFederationApiWithCache<T>
where
    T: IRawFederationApi + MaybeSend + MaybeSync + 'static,
{
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        self.inner.all_peers()
    }

    fn self_peer(&self) -> Option<PeerId> {
        self.inner.self_peer()
    }

    fn with_module(&self, id: ModuleInstanceId) -> DynModuleApi {
        self.inner.with_module(id)
    }

    /// Make request to a specific federation peer by `peer_id`
    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &[Value],
    ) -> result::Result<Value, JsonRpcClientError> {
        self.inner.request_raw(peer_id, method, params).await
    }
}

#[apply(async_trait_maybe_send!)]
impl<T> IGlobalFederationApi for GlobalFederationApiWithCache<T>
where
    T: IRawFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn await_block(
        &self,
        session_idx: u64,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionOutcome> {
        let mut lru_lock = self.await_session_lru.lock().await;

        let entry_arc = lru_lock
            .get_or_insert(session_idx, || Arc::new(OnceCell::new()))
            .clone();

        // we drop the lru lock so requests for other `session_idx` can work in parallel
        drop(lru_lock);

        entry_arc
            .get_or_try_init(|| self.await_block_raw(session_idx, decoders))
            .await
            .cloned()
    }

    async fn get_session_status(
        &self,
        session_idx: u64,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionStatus> {
        let mut lru_lock = self.get_session_status_lru.lock().await;

        let entry_arc = lru_lock
            .get_or_insert(session_idx, || Arc::new(OnceCell::new()))
            .clone();

        // we drop the lru lock so requests for other `session_idx` can work in parallel
        drop(lru_lock);

        enum NoCacheErr {
            Initial,
            Pending(Vec<AcceptedItem>),
            Err(anyhow::Error),
        }
        match entry_arc
            .get_or_try_init(|| async {
                match self.get_session_status_raw(session_idx, decoders).await {
                    Err(e) => Err(NoCacheErr::Err(e)),
                    Ok(SessionStatus::Initial) => Err(NoCacheErr::Initial),
                    Ok(SessionStatus::Pending(s)) => Err(NoCacheErr::Pending(s)),
                    // only status we can cache (hance outer Ok)
                    Ok(SessionStatus::Complete(s)) => Ok(s),
                }
            })
            .await
            .cloned()
        {
            Ok(s) => Ok(SessionStatus::Complete(s)),
            Err(NoCacheErr::Initial) => Ok(SessionStatus::Initial),
            Err(NoCacheErr::Pending(s)) => Ok(SessionStatus::Pending(s)),
            Err(NoCacheErr::Err(e)) => Err(e),
        }
    }

    /// Submit a transaction for inclusion
    async fn submit_transaction(
        &self,
        tx: Transaction,
    ) -> FederationResult<SerdeModuleEncoding<TransactionSubmissionOutcome>> {
        self.request_current_consensus(
            SUBMIT_TRANSACTION_ENDPOINT.to_owned(),
            ApiRequestErased::new(&SerdeTransaction::from(&tx)),
        )
        .await
    }

    async fn session_count(&self) -> FederationResult<u64> {
        self.request_current_consensus(
            SESSION_COUNT_ENDPOINT.to_owned(),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn await_transaction(&self, txid: TransactionId) -> FederationResult<TransactionId> {
        self.request_current_consensus(
            AWAIT_TRANSACTION_ENDPOINT.to_owned(),
            ApiRequestErased::new(txid),
        )
        .await
    }

    async fn server_config_consensus_hash(&self) -> FederationResult<sha256::Hash> {
        self.request_current_consensus(
            SERVER_CONFIG_CONSENSUS_HASH_ENDPOINT.to_owned(),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn upload_backup(&self, request: &SignedBackupRequest) -> FederationResult<()> {
        self.request_current_consensus(BACKUP_ENDPOINT.to_owned(), ApiRequestErased::new(request))
            .await
    }

    async fn download_backup(
        &self,
        id: &secp256k1::PublicKey,
    ) -> FederationResult<BTreeMap<PeerId, Option<ClientBackupSnapshot>>> {
        self.request_with_strategy(
            FilterMapThreshold::new(|_, snapshot| Ok(snapshot), self.all_peers().to_num_peers()),
            RECOVER_ENDPOINT.to_owned(),
            ApiRequestErased::new(id),
        )
        .await
    }

    async fn set_password(&self, auth: ApiAuth) -> FederationResult<()> {
        self.request_admin(SET_PASSWORD_ENDPOINT, ApiRequestErased::default(), auth)
            .await
    }

    async fn set_config_gen_connections(
        &self,
        info: ConfigGenConnectionsRequest,
        auth: ApiAuth,
    ) -> FederationResult<()> {
        self.request_admin(
            SET_CONFIG_GEN_CONNECTIONS_ENDPOINT,
            ApiRequestErased::new(info),
            auth,
        )
        .await
    }

    async fn add_config_gen_peer(&self, peer: PeerServerParams) -> FederationResult<()> {
        self.request_admin_no_auth(ADD_CONFIG_GEN_PEER_ENDPOINT, ApiRequestErased::new(peer))
            .await
    }

    async fn get_config_gen_peers(&self) -> FederationResult<Vec<PeerServerParams>> {
        self.request_admin_no_auth(CONFIG_GEN_PEERS_ENDPOINT, ApiRequestErased::default())
            .await
    }

    async fn get_default_config_gen_params(
        &self,
        auth: ApiAuth,
    ) -> FederationResult<ConfigGenParamsRequest> {
        self.request_admin(
            DEFAULT_CONFIG_GEN_PARAMS_ENDPOINT,
            ApiRequestErased::default(),
            auth,
        )
        .await
    }

    async fn set_config_gen_params(
        &self,
        requested: ConfigGenParamsRequest,
        auth: ApiAuth,
    ) -> FederationResult<()> {
        self.request_admin(
            SET_CONFIG_GEN_PARAMS_ENDPOINT,
            ApiRequestErased::new(requested),
            auth,
        )
        .await
    }

    async fn consensus_config_gen_params(&self) -> FederationResult<ConfigGenParamsResponse> {
        self.request_admin_no_auth(
            CONSENSUS_CONFIG_GEN_PARAMS_ENDPOINT,
            ApiRequestErased::default(),
        )
        .await
    }

    async fn run_dkg(&self, auth: ApiAuth) -> FederationResult<()> {
        self.request_admin(RUN_DKG_ENDPOINT, ApiRequestErased::default(), auth)
            .await
    }

    async fn get_verify_config_hash(
        &self,
        auth: ApiAuth,
    ) -> FederationResult<BTreeMap<PeerId, sha256::Hash>> {
        self.request_admin(
            VERIFY_CONFIG_HASH_ENDPOINT,
            ApiRequestErased::default(),
            auth,
        )
        .await
    }

    async fn verified_configs(
        &self,
        auth: ApiAuth,
    ) -> FederationResult<BTreeMap<PeerId, sha256::Hash>> {
        self.request_admin(VERIFIED_CONFIGS_ENDPOINT, ApiRequestErased::default(), auth)
            .await
    }

    async fn start_consensus(&self, auth: ApiAuth) -> FederationResult<()> {
        self.request_admin(START_CONSENSUS_ENDPOINT, ApiRequestErased::default(), auth)
            .await
    }

    async fn status(&self) -> FederationResult<StatusResponse> {
        self.request_admin_no_auth(STATUS_ENDPOINT, ApiRequestErased::default())
            .await
    }

    async fn audit(&self, auth: ApiAuth) -> FederationResult<AuditSummary> {
        self.request_admin(AUDIT_ENDPOINT, ApiRequestErased::default(), auth)
            .await
    }

    async fn guardian_config_backup(
        &self,
        auth: ApiAuth,
    ) -> FederationResult<GuardianConfigBackup> {
        self.request_admin(
            GUARDIAN_CONFIG_BACKUP_ENDPOINT,
            ApiRequestErased::default(),
            auth,
        )
        .await
    }

    async fn auth(&self, auth: ApiAuth) -> FederationResult<()> {
        self.request_admin(AUTH_ENDPOINT, ApiRequestErased::default(), auth)
            .await
    }

    async fn restart_federation_setup(&self, auth: ApiAuth) -> FederationResult<()> {
        self.request_admin(
            RESTART_FEDERATION_SETUP_ENDPOINT,
            ApiRequestErased::default(),
            auth,
        )
        .await
    }

    async fn submit_api_announcement(
        &self,
        announcement_peer_id: PeerId,
        announcement: SignedApiAnnouncement,
    ) -> FederationResult<()> {
        let peer_errors = join_all(self.all_peers().iter().map(|&peer_id| {
            let announcement_inner = announcement.clone();
            async move {
                (
                    peer_id,
                    self.request_single_peer(
                        None,
                        SUBMIT_API_ANNOUNCEMENT_ENDPOINT.into(),
                        ApiRequestErased::new(SignedApiAnnouncementSubmission {
                            signed_api_announcement: announcement_inner,
                            peer_id: announcement_peer_id,
                        }),
                        peer_id,
                    )
                    .await,
                )
            }
        }))
        .await
        .into_iter()
        .filter_map(|(peer_id, result)| match result {
            Ok(_) => None,
            Err(e) => Some((peer_id, e.into())),
        })
        .collect::<BTreeMap<_, _>>();

        if peer_errors.is_empty() {
            Ok(())
        } else {
            Err(FederationError {
                method: SUBMIT_API_ANNOUNCEMENT_ENDPOINT.to_string(),
                params: serde_json::to_value(announcement).expect("can be serialized"),
                general: None,
                peers: peer_errors,
            })
        }
    }

    async fn api_announcements(
        &self,
        guardian: PeerId,
    ) -> PeerResult<BTreeMap<PeerId, SignedApiAnnouncement>> {
        self.request_single_peer_typed(
            None,
            API_ANNOUNCEMENTS_ENDPOINT.to_owned(),
            ApiRequestErased::default(),
            guardian,
        )
        .await
    }

    async fn sign_api_announcement(
        &self,
        api_url: SafeUrl,
        auth: ApiAuth,
    ) -> FederationResult<SignedApiAnnouncement> {
        self.request_admin(
            SIGN_API_ANNOUNCEMENT_ENDPOINT,
            ApiRequestErased::new(api_url),
            auth,
        )
        .await
    }

    async fn shutdown(&self, session: Option<u64>, auth: ApiAuth) -> FederationResult<()> {
        self.request_admin(SHUTDOWN_ENDPOINT, ApiRequestErased::new(session), auth)
            .await
    }
}
