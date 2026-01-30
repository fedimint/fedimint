use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::{anyhow, format_err};
use bitcoin::secp256k1;
use fedimint_connectors::ServerResult;
use fedimint_core::admin_client::{GuardianConfigBackup, SetLocalParamsRequest, SetupStatus};
use fedimint_core::backup::{BackupStatistics, ClientBackupSnapshot};
use fedimint_core::core::backup::SignedBackupRequest;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::endpoint_constants::{
    ADD_PEER_SETUP_CODE_ENDPOINT, API_ANNOUNCEMENTS_ENDPOINT, AUDIT_ENDPOINT, AUTH_ENDPOINT,
    AWAIT_SESSION_OUTCOME_ENDPOINT, AWAIT_TRANSACTION_ENDPOINT, BACKUP_ENDPOINT,
    BACKUP_STATISTICS_ENDPOINT, CHAIN_ID_ENDPOINT, CHANGE_PASSWORD_ENDPOINT,
    FEDIMINTD_VERSION_ENDPOINT, GET_SETUP_CODE_ENDPOINT, GUARDIAN_CONFIG_BACKUP_ENDPOINT,
    INVITE_CODE_ENDPOINT, RECOVER_ENDPOINT, RESET_PEER_SETUP_CODES_ENDPOINT,
    RESTART_FEDERATION_SETUP_ENDPOINT, SESSION_COUNT_ENDPOINT, SESSION_STATUS_ENDPOINT,
    SESSION_STATUS_V2_ENDPOINT, SET_LOCAL_PARAMS_ENDPOINT, SET_PASSWORD_ENDPOINT,
    SETUP_STATUS_ENDPOINT, SHUTDOWN_ENDPOINT, SIGN_API_ANNOUNCEMENT_ENDPOINT, START_DKG_ENDPOINT,
    STATUS_ENDPOINT, SUBMIT_API_ANNOUNCEMENT_ENDPOINT, SUBMIT_TRANSACTION_ENDPOINT,
};
use fedimint_core::endpoint_constants::{
    ADD_PEER_SETUP_CODE_ENDPOINT, API_ANNOUNCEMENTS_ENDPOINT, AUDIT_ENDPOINT, AUTH_ENDPOINT,
    AWAIT_SESSION_OUTCOME_ENDPOINT, AWAIT_TRANSACTION_ENDPOINT, BACKUP_ENDPOINT,
    BACKUP_STATISTICS_ENDPOINT, CHANGE_PASSWORD_ENDPOINT, FEDIMINTD_VERSION_ENDPOINT,
    GET_SETUP_CODE_ENDPOINT, GUARDIAN_CONFIG_BACKUP_ENDPOINT, GUARDIAN_METADATA_ENDPOINT,
    INVITE_CODE_ENDPOINT, RECOVER_ENDPOINT, RESET_PEER_SETUP_CODES_ENDPOINT,
    RESTART_FEDERATION_SETUP_ENDPOINT, SESSION_COUNT_ENDPOINT, SESSION_STATUS_ENDPOINT,
    SESSION_STATUS_V2_ENDPOINT, SET_LOCAL_PARAMS_ENDPOINT, SET_PASSWORD_ENDPOINT,
    SETUP_STATUS_ENDPOINT, SHUTDOWN_ENDPOINT, SIGN_API_ANNOUNCEMENT_ENDPOINT,
    SIGN_GUARDIAN_METADATA_ENDPOINT, START_DKG_ENDPOINT, STATUS_ENDPOINT,
    SUBMIT_API_ANNOUNCEMENT_ENDPOINT, SUBMIT_GUARDIAN_METADATA_ENDPOINT,
    SUBMIT_TRANSACTION_ENDPOINT, SUBMIT_TRANSACTION_ENDPOINT,
};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::audit::AuditSummary;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{
    ApiAuth, ApiRequestErased, ApiVersion, SerdeModuleEncoding, SerdeModuleEncodingBase64,
};
use fedimint_core::net::api_announcement::{
    SignedApiAnnouncement, SignedApiAnnouncementSubmission,
};
use fedimint_core::session_outcome::{
    AcceptedItem, SessionOutcome, SessionStatus, SessionStatusV2,
};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::transaction::{SerdeTransaction, Transaction, TransactionSubmissionOutcome};
use fedimint_core::util::SafeUrl;
use fedimint_core::{ChainId, NumPeersExt, PeerId, TransactionId, apply, async_trait_maybe_send};
use fedimint_logging::LOG_CLIENT_NET_API;
use futures::future::join_all;
use futures::stream::BoxStream;
use itertools::Itertools;
use rand::seq::SliceRandom;
use serde_json::Value;
use tokio::sync::OnceCell;
use tracing::{debug, trace};

use super::super::{DynModuleApi, IGlobalFederationApi, IRawFederationApi, StatusResponse};
use crate::api::{
    FederationApiExt, FederationError, FederationResult,
    VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2,
};
use crate::query::FilterMapThreshold;

/// Convenience extension trait used for wrapping [`IRawFederationApi`] in
/// a [`GlobalFederationApiWithCache`]
pub trait GlobalFederationApiWithCacheExt
where
    Self: Sized,
{
    fn with_cache(self) -> GlobalFederationApiWithCache<Self>;
}

impl<T> GlobalFederationApiWithCacheExt for T
where
    T: IRawFederationApi + MaybeSend + MaybeSync + 'static,
{
    fn with_cache(self) -> GlobalFederationApiWithCache<T> {
        GlobalFederationApiWithCache::new(self)
    }
}

/// [`IGlobalFederationApi`] wrapping some `T: IRawFederationApi` and adding
/// a tiny bit of caching.
///
/// Use [`GlobalFederationApiWithCacheExt::with_cache`] to create.
#[derive(Debug)]
pub struct GlobalFederationApiWithCache<T> {
    pub(crate) inner: T,
    /// Small LRU used as [`IGlobalFederationApi::await_block`] cache.
    ///
    /// This is mostly to avoid multiple client module recovery processes
    /// re-requesting same blocks and putting burden on the federation.
    ///
    /// The LRU can be be fairly small, as if the modules are
    /// (near-)bottlenecked on fetching blocks they will naturally
    /// synchronize, or split into a handful of groups. And if they are not,
    /// no LRU here is going to help them.
    pub(crate) await_session_lru:
        Arc<tokio::sync::Mutex<lru::LruCache<u64, Arc<OnceCell<SessionOutcome>>>>>,

    /// Like [`Self::await_session_lru`], but for
    /// [`IGlobalFederationApi::get_session_status`].
    ///
    /// In theory these two LRUs have the same content, but one is locked by
    /// potentially long-blocking operation, while the other non-blocking one.
    /// Given how tiny they are, it's not worth complicating things to unify
    /// them.
    pub(crate) get_session_status_lru:
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
    pub(crate) async fn await_block_raw(
        &self,
        block_index: u64,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionOutcome> {
        if block_index % 100 == 0 {
            debug!(target: LOG_CLIENT_NET_API, block_index, "Awaiting block's outcome from Federation");
        } else {
            trace!(target: LOG_CLIENT_NET_API, block_index, "Awaiting block's outcome from Federation");
        }
        self.request_current_consensus::<SerdeModuleEncoding<SessionOutcome>>(
            AWAIT_SESSION_OUTCOME_ENDPOINT.to_string(),
            ApiRequestErased::new(block_index),
        )
        .await?
        .try_into_inner(decoders)
        .map_err(|e| anyhow!(e.to_string()))
    }

    pub(crate) fn select_peers_for_status(&self) -> impl Iterator<Item = PeerId> + '_ {
        let mut peers = self.all_peers().iter().copied().collect_vec();
        peers.shuffle(&mut rand::thread_rng());
        peers.into_iter()
    }

    pub(crate) async fn get_session_status_raw_v2(
        &self,
        block_index: u64,
        broadcast_public_keys: &BTreeMap<PeerId, secp256k1::PublicKey>,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionStatus> {
        if block_index % 100 == 0 {
            debug!(target: LOG_CLIENT_NET_API, block_index, "Get session status raw v2");
        } else {
            trace!(target: LOG_CLIENT_NET_API, block_index, "Get session status raw v2");
        }
        let params = ApiRequestErased::new(block_index);
        let mut last_error = None;
        // fetch serially
        for peer_id in self.select_peers_for_status() {
            match self
                .request_single_peer_federation::<SerdeModuleEncodingBase64<SessionStatusV2>>(
                    SESSION_STATUS_V2_ENDPOINT.to_string(),
                    params.clone(),
                    peer_id,
                )
                .await
                .map_err(anyhow::Error::from)
                .and_then(|s| Ok(s.try_into_inner(decoders)?))
            {
                Ok(SessionStatusV2::Complete(signed_session_outcome)) => {
                    if signed_session_outcome.verify(broadcast_public_keys, block_index) {
                        // early return
                        return Ok(SessionStatus::Complete(
                            signed_session_outcome.session_outcome,
                        ));
                    }
                    last_error = Some(format_err!("Invalid signature"));
                }
                Ok(SessionStatusV2::Initial | SessionStatusV2::Pending(..)) => {
                    // no signature: use fallback method
                    return self.get_session_status_raw(block_index, decoders).await;
                }
                Err(err) => {
                    last_error = Some(err);
                }
            }
            // if we loop then we must have last_error
            assert!(last_error.is_some());
        }
        Err(last_error.expect("must have at least one peer"))
    }

    pub(crate) async fn get_session_status_raw(
        &self,
        block_index: u64,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionStatus> {
        if block_index % 100 == 0 {
            debug!(target: LOG_CLIENT_NET_API, block_index, "Get session status raw v1");
        } else {
            trace!(target: LOG_CLIENT_NET_API, block_index, "Get session status raw v1");
        }
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
        params: &ApiRequestErased,
    ) -> ServerResult<Value> {
        self.inner.request_raw(peer_id, method, params).await
    }

    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, bool>> {
        self.inner.connection_status_stream()
    }

    async fn wait_for_initialized_connections(&self) {
        self.inner.wait_for_initialized_connections().await;
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
        core_api_version: ApiVersion,
        broadcast_public_keys: Option<&BTreeMap<PeerId, secp256k1::PublicKey>>,
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
                let session_status =
                    if core_api_version < VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2 {
                        self.get_session_status_raw(session_idx, decoders).await
                    } else if let Some(broadcast_public_keys) = broadcast_public_keys {
                        self.get_session_status_raw_v2(session_idx, broadcast_public_keys, decoders)
                            .await
                    } else {
                        self.get_session_status_raw(session_idx, decoders).await
                    };
                match session_status {
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

    async fn submit_transaction(
        &self,
        tx: Transaction,
    ) -> SerdeModuleEncoding<TransactionSubmissionOutcome> {
        self.request_current_consensus_retry(
            SUBMIT_TRANSACTION_ENDPOINT.to_owned(),
            ApiRequestErased::new(SerdeTransaction::from(&tx)),
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

    async fn await_transaction(&self, txid: TransactionId) -> TransactionId {
        self.request_current_consensus_retry(
            AWAIT_TRANSACTION_ENDPOINT.to_owned(),
            ApiRequestErased::new(txid),
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

    async fn setup_status(&self, auth: ApiAuth) -> FederationResult<SetupStatus> {
        self.request_admin(SETUP_STATUS_ENDPOINT, ApiRequestErased::default(), auth)
            .await
    }

    async fn set_local_params(
        &self,
        name: String,
        federation_name: Option<String>,
        disable_base_fees: Option<bool>,
        enabled_modules: Option<BTreeSet<ModuleKind>>,
        auth: ApiAuth,
    ) -> FederationResult<String> {
        self.request_admin(
            SET_LOCAL_PARAMS_ENDPOINT,
            ApiRequestErased::new(SetLocalParamsRequest {
                name,
                federation_name,
                disable_base_fees,
                enabled_modules,
            }),
            auth,
        )
        .await
    }

    async fn add_peer_connection_info(
        &self,
        info: String,
        auth: ApiAuth,
    ) -> FederationResult<String> {
        self.request_admin(
            ADD_PEER_SETUP_CODE_ENDPOINT,
            ApiRequestErased::new(info),
            auth,
        )
        .await
    }

    async fn reset_peer_setup_codes(&self, auth: ApiAuth) -> FederationResult<()> {
        self.request_admin(
            RESET_PEER_SETUP_CODES_ENDPOINT,
            ApiRequestErased::default(),
            auth,
        )
        .await
    }

    async fn get_setup_code(&self, auth: ApiAuth) -> FederationResult<Option<String>> {
        self.request_admin(GET_SETUP_CODE_ENDPOINT, ApiRequestErased::default(), auth)
            .await
    }

    async fn start_dkg(&self, auth: ApiAuth) -> FederationResult<()> {
        self.request_admin(START_DKG_ENDPOINT, ApiRequestErased::default(), auth)
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
                    self.request_single_peer::<()>(
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
            Ok(()) => None,
            Err(e) => Some((peer_id, e)),
        })
        .collect::<BTreeMap<_, _>>();

        if peer_errors.is_empty() {
            Ok(())
        } else {
            Err(FederationError {
                method: SUBMIT_API_ANNOUNCEMENT_ENDPOINT.to_string(),
                params: serde_json::to_value(announcement).expect("can be serialized"),
                general: None,
                peer_errors,
            })
        }
    }

    async fn api_announcements(
        &self,
        guardian: PeerId,
    ) -> ServerResult<BTreeMap<PeerId, SignedApiAnnouncement>> {
        self.request_single_peer(
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

    async fn submit_guardian_metadata(
        &self,
        announcement_peer_id: PeerId,
        metadata: fedimint_core::net::guardian_metadata::SignedGuardianMetadata,
    ) -> FederationResult<()> {
        use fedimint_core::net::guardian_metadata::SignedGuardianMetadataSubmission;
        let peer_errors = join_all(self.all_peers().iter().map(|&peer_id| {
            let metadata_inner = metadata.clone();
            async move {
                (
                    peer_id,
                    self.request_single_peer::<()>(
                        SUBMIT_GUARDIAN_METADATA_ENDPOINT.into(),
                        ApiRequestErased::new(SignedGuardianMetadataSubmission {
                            signed_guardian_metadata: metadata_inner,
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
            Ok(()) => None,
            Err(e) => Some((peer_id, e)),
        })
        .collect::<BTreeMap<_, _>>();

        if peer_errors.is_empty() {
            Ok(())
        } else {
            Err(FederationError {
                method: SUBMIT_GUARDIAN_METADATA_ENDPOINT.to_string(),
                params: serde_json::to_value(&metadata).expect("can be serialized"),
                general: None,
                peer_errors,
            })
        }
    }

    async fn guardian_metadata(
        &self,
        guardian: PeerId,
    ) -> ServerResult<BTreeMap<PeerId, fedimint_core::net::guardian_metadata::SignedGuardianMetadata>>
    {
        self.request_single_peer(
            GUARDIAN_METADATA_ENDPOINT.to_owned(),
            ApiRequestErased::default(),
            guardian,
        )
        .await
    }

    async fn sign_guardian_metadata(
        &self,
        metadata: fedimint_core::net::guardian_metadata::GuardianMetadata,
        auth: ApiAuth,
    ) -> FederationResult<fedimint_core::net::guardian_metadata::SignedGuardianMetadata> {
        self.request_admin(
            SIGN_GUARDIAN_METADATA_ENDPOINT,
            ApiRequestErased::new(metadata),
            auth,
        )
        .await
    }

    async fn shutdown(&self, session: Option<u64>, auth: ApiAuth) -> FederationResult<()> {
        self.request_admin(SHUTDOWN_ENDPOINT, ApiRequestErased::new(session), auth)
            .await
    }

    async fn backup_statistics(&self, auth: ApiAuth) -> FederationResult<BackupStatistics> {
        self.request_admin(
            BACKUP_STATISTICS_ENDPOINT,
            ApiRequestErased::default(),
            auth,
        )
        .await
    }

    async fn fedimintd_version(&self, peer_id: PeerId) -> ServerResult<String> {
        self.request_single_peer(
            FEDIMINTD_VERSION_ENDPOINT.to_owned(),
            ApiRequestErased::default(),
            peer_id,
        )
        .await
    }

    async fn get_invite_code(&self, guardian: PeerId) -> ServerResult<InviteCode> {
        self.request_single_peer(
            INVITE_CODE_ENDPOINT.to_owned(),
            ApiRequestErased::default(),
            guardian,
        )
        .await
    }

    async fn change_password(&self, auth: ApiAuth, new_password: &str) -> FederationResult<()> {
        self.request_admin(
            CHANGE_PASSWORD_ENDPOINT,
            ApiRequestErased::new(new_password),
            auth,
        )
        .await
    }

    async fn chain_id(&self) -> FederationResult<ChainId> {
        self.request_current_consensus(CHAIN_ID_ENDPOINT.to_owned(), ApiRequestErased::default())
            .await
    }
}
