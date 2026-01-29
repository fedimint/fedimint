mod error;
pub mod global_api;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::future::pending;
use std::pin::Pin;
use std::result;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use bitcoin::secp256k1;
pub use error::{FederationError, OutputOutcomeError};
pub use fedimint_connectors::ServerResult;
pub use fedimint_connectors::error::ServerError;
use fedimint_connectors::{
    ConnectionPool, ConnectorRegistry, DynGuaridianConnection, IGuardianConnection,
};
use fedimint_core::admin_client::{GuardianConfigBackup, ServerStatusLegacy, SetupStatus};
use fedimint_core::backup::{BackupStatistics, ClientBackupSnapshot};
use fedimint_core::core::backup::SignedBackupRequest;
use fedimint_core::core::{Decoder, DynOutputOutcome, ModuleInstanceId, ModuleKind, OutputOutcome};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::audit::AuditSummary;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{
    ApiAuth, ApiMethod, ApiRequestErased, ApiVersion, SerdeModuleEncoding,
};
use fedimint_core::net::api_announcement::SignedApiAnnouncement;
use fedimint_core::session_outcome::{SessionOutcome, SessionStatus};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::transaction::{Transaction, TransactionSubmissionOutcome};
use fedimint_core::util::backoff_util::api_networking_backoff;
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_core::{
    ChainId, NumPeersExt, PeerId, TransactionId, apply, async_trait_maybe_send, dyn_newtype_define,
    util,
};
use fedimint_logging::LOG_CLIENT_NET_API;
use fedimint_metrics::HistogramExt as _;
use futures::stream::{BoxStream, FuturesUnordered};
use futures::{Future, StreamExt};
use global_api::with_cache::GlobalFederationApiWithCache;
use jsonrpsee_core::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;
use tokio_stream::wrappers::WatchStream;
use tracing::{debug, instrument, trace, warn};

use crate::metrics::{CLIENT_API_REQUEST_DURATION_SECONDS, CLIENT_API_REQUESTS_TOTAL};
use crate::query::{QueryStep, QueryStrategy, ThresholdConsensus};

pub const VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2: ApiVersion = ApiVersion::new(0, 5);

pub const VERSION_THAT_INTRODUCED_GET_SESSION_STATUS: ApiVersion =
    ApiVersion { major: 0, minor: 1 };

pub const VERSION_THAT_INTRODUCED_AWAIT_OUTPUTS_OUTCOMES: ApiVersion = ApiVersion::new(0, 8);
pub type FederationResult<T> = Result<T, FederationError>;
pub type SerdeOutputOutcome = SerdeModuleEncoding<DynOutputOutcome>;

pub type OutputOutcomeResult<O> = result::Result<O, OutputOutcomeError>;

/// Set of api versions for each component (core + modules)
///
/// E.g. result of federated common api versions discovery.
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct ApiVersionSet {
    pub core: ApiVersion,
    pub modules: BTreeMap<ModuleInstanceId, ApiVersion>,
}

/// An API (module or global) that can query a federation
#[apply(async_trait_maybe_send!)]
pub trait IRawFederationApi: Debug + MaybeSend + MaybeSync {
    /// List of all federation peers for the purpose of iterating each peer
    /// in the federation.
    ///
    /// The underlying implementation is responsible for knowing how many
    /// and `PeerId`s of each. The caller of this interface most probably
    /// have some idea as well, but passing this set across every
    /// API call to the federation would be inconvenient.
    fn all_peers(&self) -> &BTreeSet<PeerId>;

    /// `PeerId` of the Guardian node, if set
    ///
    /// This is for using Client in a "Admin" mode, making authenticated
    /// calls to own `fedimintd` instance.
    fn self_peer(&self) -> Option<PeerId>;

    fn with_module(&self, id: ModuleInstanceId) -> DynModuleApi;

    /// Make request to a specific federation peer by `peer_id`
    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> ServerResult<Value>;

    /// Returns a stream of connection status for each peer
    ///
    /// The stream emits a new value whenever the connection status changes.
    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, bool>>;
    /// Wait for some connections being initialized
    ///
    /// This is useful to avoid initializing networking by
    /// tasks that are not high priority.
    async fn wait_for_initialized_connections(&self);
}

/// An extension trait allowing to making federation-wide API call on top
/// [`IRawFederationApi`].
#[apply(async_trait_maybe_send!)]
pub trait FederationApiExt: IRawFederationApi {
    async fn request_single_peer<Ret>(
        &self,
        method: String,
        params: ApiRequestErased,
        peer: PeerId,
    ) -> ServerResult<Ret>
    where
        Ret: DeserializeOwned,
    {
        self.request_raw(peer, &method, &params)
            .await
            .and_then(|v| {
                serde_json::from_value(v)
                    .map_err(|e| ServerError::ResponseDeserialization(e.into()))
            })
    }

    async fn request_single_peer_federation<FedRet>(
        &self,
        method: String,
        params: ApiRequestErased,
        peer_id: PeerId,
    ) -> FederationResult<FedRet>
    where
        FedRet: serde::de::DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        self.request_raw(peer_id, &method, &params)
            .await
            .and_then(|v| {
                serde_json::from_value(v)
                    .map_err(|e| ServerError::ResponseDeserialization(e.into()))
            })
            .map_err(|e| error::FederationError::new_one_peer(peer_id, method, params, e))
    }

    /// Make an aggregate request to federation, using `strategy` to logically
    /// merge the responses.
    #[instrument(target = LOG_CLIENT_NET_API, skip_all, fields(method=method))]
    async fn request_with_strategy<PR: DeserializeOwned, FR: Debug>(
        &self,
        mut strategy: impl QueryStrategy<PR, FR> + MaybeSend,
        method: String,
        params: ApiRequestErased,
    ) -> FederationResult<FR> {
        // NOTE: `FuturesUnorderded` is a footgun, but all we do here is polling
        // completed results from it and we don't do any `await`s when
        // processing them, it should be totally OK.
        #[cfg(not(target_family = "wasm"))]
        let mut futures = FuturesUnordered::<Pin<Box<dyn Future<Output = _> + Send>>>::new();
        #[cfg(target_family = "wasm")]
        let mut futures = FuturesUnordered::<Pin<Box<dyn Future<Output = _>>>>::new();

        for peer in self.all_peers() {
            futures.push(Box::pin({
                let method = &method;
                let params = &params;
                async move {
                    let result = self
                        .request_single_peer(method.clone(), params.clone(), *peer)
                        .await;

                    (*peer, result)
                }
            }));
        }

        let mut peer_errors = BTreeMap::new();
        let peer_error_threshold = self.all_peers().to_num_peers().one_honest();

        loop {
            let (peer, result) = futures
                .next()
                .await
                .expect("Query strategy ran out of peers to query without returning a result");

            match result {
                Ok(response) => match strategy.process(peer, response) {
                    QueryStep::Retry(peers) => {
                        for peer in peers {
                            futures.push(Box::pin({
                                let method = &method;
                                let params = &params;
                                async move {
                                    let result = self
                                        .request_single_peer(method.clone(), params.clone(), peer)
                                        .await;

                                    (peer, result)
                                }
                            }));
                        }
                    }
                    QueryStep::Success(response) => return Ok(response),
                    QueryStep::Failure(e) => {
                        peer_errors.insert(peer, e);
                    }
                    QueryStep::Continue => {}
                },
                Err(e) => {
                    e.report_if_unusual(peer, "RequestWithStrategy");
                    peer_errors.insert(peer, e);
                }
            }

            if peer_errors.len() == peer_error_threshold {
                return Err(FederationError::peer_errors(
                    method.clone(),
                    params.params.clone(),
                    peer_errors,
                ));
            }
        }
    }

    #[instrument(target = LOG_CLIENT_NET_API, level = "debug", skip(self, strategy))]
    async fn request_with_strategy_retry<PR: DeserializeOwned + MaybeSend, FR: Debug>(
        &self,
        mut strategy: impl QueryStrategy<PR, FR> + MaybeSend,
        method: String,
        params: ApiRequestErased,
    ) -> FR {
        // NOTE: `FuturesUnorderded` is a footgun, but all we do here is polling
        // completed results from it and we don't do any `await`s when
        // processing them, it should be totally OK.
        #[cfg(not(target_family = "wasm"))]
        let mut futures = FuturesUnordered::<Pin<Box<dyn Future<Output = _> + Send>>>::new();
        #[cfg(target_family = "wasm")]
        let mut futures = FuturesUnordered::<Pin<Box<dyn Future<Output = _>>>>::new();

        for peer in self.all_peers() {
            futures.push(Box::pin({
                let method = &method;
                let params = &params;
                async move {
                    let response = util::retry(
                        format!("api-request-{method}-{peer}"),
                        api_networking_backoff(),
                        || async {
                            self.request_single_peer(method.clone(), params.clone(), *peer)
                                .await
                                .inspect_err(|e| {
                                    e.report_if_unusual(*peer, "QueryWithStrategyRetry");
                                })
                                .map_err(|e| anyhow!(e.to_string()))
                        },
                    )
                    .await
                    .expect("Number of retries has no limit");

                    (*peer, response)
                }
            }));
        }

        loop {
            let (peer, response) = match futures.next().await {
                Some(t) => t,
                None => pending().await,
            };

            match strategy.process(peer, response) {
                QueryStep::Retry(peers) => {
                    for peer in peers {
                        futures.push(Box::pin({
                            let method = &method;
                            let params = &params;
                            async move {
                                let response = util::retry(
                                    format!("api-request-{method}-{peer}"),
                                    api_networking_backoff(),
                                    || async {
                                        self.request_single_peer(
                                            method.clone(),
                                            params.clone(),
                                            peer,
                                        )
                                        .await
                                        .inspect_err(|err| {
                                            if err.is_unusual() {
                                                debug!(target: LOG_CLIENT_NET_API, err = %err.fmt_compact(), "Unusual peer error");
                                            }
                                        })
                                        .map_err(|e| anyhow!(e.to_string()))
                                    },
                                )
                                .await
                                .expect("Number of retries has no limit");

                                (peer, response)
                            }
                        }));
                    }
                }
                QueryStep::Success(response) => return response,
                QueryStep::Failure(e) => {
                    warn!(target: LOG_CLIENT_NET_API, "Query strategy returned non-retryable failure for peer {peer}: {e}");
                }
                QueryStep::Continue => {}
            }
        }
    }

    async fn request_current_consensus<Ret>(
        &self,
        method: String,
        params: ApiRequestErased,
    ) -> FederationResult<Ret>
    where
        Ret: DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        self.request_with_strategy(
            ThresholdConsensus::new(self.all_peers().to_num_peers()),
            method,
            params,
        )
        .await
    }

    async fn request_current_consensus_retry<Ret>(
        &self,
        method: String,
        params: ApiRequestErased,
    ) -> Ret
    where
        Ret: DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        self.request_with_strategy_retry(
            ThresholdConsensus::new(self.all_peers().to_num_peers()),
            method,
            params,
        )
        .await
    }

    async fn request_admin<Ret>(
        &self,
        method: &str,
        params: ApiRequestErased,
        auth: ApiAuth,
    ) -> FederationResult<Ret>
    where
        Ret: DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        let Some(self_peer_id) = self.self_peer() else {
            return Err(FederationError::general(
                method,
                params,
                anyhow::format_err!("Admin peer_id not set"),
            ));
        };

        self.request_single_peer_federation(method.into(), params.with_auth(auth), self_peer_id)
            .await
    }

    async fn request_admin_no_auth<Ret>(
        &self,
        method: &str,
        params: ApiRequestErased,
    ) -> FederationResult<Ret>
    where
        Ret: DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        let Some(self_peer_id) = self.self_peer() else {
            return Err(FederationError::general(
                method,
                params,
                anyhow::format_err!("Admin peer_id not set"),
            ));
        };

        self.request_single_peer_federation(method.into(), params, self_peer_id)
            .await
    }
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> FederationApiExt for T where T: IRawFederationApi {}

/// Trait marker for the module (non-global) endpoints
pub trait IModuleFederationApi: IRawFederationApi {}

dyn_newtype_define! {
    #[derive(Clone)]
    pub DynModuleApi(Arc<IModuleFederationApi>)
}

dyn_newtype_define! {
    #[derive(Clone)]
    pub DynGlobalApi(Arc<IGlobalFederationApi>)
}

impl AsRef<dyn IGlobalFederationApi + 'static> for DynGlobalApi {
    fn as_ref(&self) -> &(dyn IGlobalFederationApi + 'static) {
        self.inner.as_ref()
    }
}

impl DynGlobalApi {
    pub fn new(
        connectors: ConnectorRegistry,
        peers: BTreeMap<PeerId, SafeUrl>,
        api_secret: Option<&str>,
    ) -> anyhow::Result<Self> {
        Ok(GlobalFederationApiWithCache::new(FederationApi::new(
            connectors, peers, None, api_secret,
        ))
        .into())
    }
    pub fn new_admin(
        connectors: ConnectorRegistry,
        peer: PeerId,
        url: SafeUrl,
        api_secret: Option<&str>,
    ) -> anyhow::Result<DynGlobalApi> {
        Ok(GlobalFederationApiWithCache::new(FederationApi::new(
            connectors,
            [(peer, url)].into(),
            Some(peer),
            api_secret,
        ))
        .into())
    }

    pub fn new_admin_setup(connectors: ConnectorRegistry, url: SafeUrl) -> anyhow::Result<Self> {
        // PeerIds are used only for informational purposes, but just in case, make a
        // big number so it stands out
        Self::new_admin(
            connectors,
            PeerId::from(1024),
            url,
            // Setup does not have api secrets yet
            None,
        )
    }
}

/// The API for the global (non-module) endpoints
#[apply(async_trait_maybe_send!)]
pub trait IGlobalFederationApi: IRawFederationApi {
    async fn submit_transaction(
        &self,
        tx: Transaction,
    ) -> SerdeModuleEncoding<TransactionSubmissionOutcome>;

    async fn await_block(
        &self,
        block_index: u64,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionOutcome>;

    async fn get_session_status(
        &self,
        block_index: u64,
        decoders: &ModuleDecoderRegistry,
        core_api_version: ApiVersion,
        broadcast_public_keys: Option<&BTreeMap<PeerId, secp256k1::PublicKey>>,
    ) -> anyhow::Result<SessionStatus>;

    async fn session_count(&self) -> FederationResult<u64>;

    async fn await_transaction(&self, txid: TransactionId) -> TransactionId;

    async fn upload_backup(&self, request: &SignedBackupRequest) -> FederationResult<()>;

    async fn download_backup(
        &self,
        id: &secp256k1::PublicKey,
    ) -> FederationResult<BTreeMap<PeerId, Option<ClientBackupSnapshot>>>;

    /// Sets the password used to decrypt the configs and authenticate
    ///
    /// Must be called first before any other calls to the API
    async fn set_password(&self, auth: ApiAuth) -> FederationResult<()>;

    async fn setup_status(&self, auth: ApiAuth) -> FederationResult<SetupStatus>;

    async fn set_local_params(
        &self,
        name: String,
        federation_name: Option<String>,
        disable_base_fees: Option<bool>,
        enabled_modules: Option<BTreeSet<ModuleKind>>,
        auth: ApiAuth,
    ) -> FederationResult<String>;

    async fn add_peer_connection_info(
        &self,
        info: String,
        auth: ApiAuth,
    ) -> FederationResult<String>;

    /// Reset the peer setup codes during the federation setup process
    async fn reset_peer_setup_codes(&self, auth: ApiAuth) -> FederationResult<()>;

    /// Returns the setup code if `set_local_params` was already called
    async fn get_setup_code(&self, auth: ApiAuth) -> FederationResult<Option<String>>;

    /// Runs DKG, can only be called once after configs have been generated in
    /// `get_consensus_config_gen_params`.  If DKG fails this returns a 500
    /// error and config gen must be restarted.
    async fn start_dkg(&self, auth: ApiAuth) -> FederationResult<()>;

    /// Returns the status of the server
    async fn status(&self) -> FederationResult<StatusResponse>;

    /// Show an audit across all modules
    async fn audit(&self, auth: ApiAuth) -> FederationResult<AuditSummary>;

    /// Download the guardian config to back it up
    async fn guardian_config_backup(&self, auth: ApiAuth)
    -> FederationResult<GuardianConfigBackup>;

    /// Check auth credentials
    async fn auth(&self, auth: ApiAuth) -> FederationResult<()>;

    async fn restart_federation_setup(&self, auth: ApiAuth) -> FederationResult<()>;

    /// Publish our signed API announcement to other guardians
    async fn submit_api_announcement(
        &self,
        peer_id: PeerId,
        announcement: SignedApiAnnouncement,
    ) -> FederationResult<()>;

    async fn api_announcements(
        &self,
        guardian: PeerId,
    ) -> ServerResult<BTreeMap<PeerId, SignedApiAnnouncement>>;

    async fn sign_api_announcement(
        &self,
        api_url: SafeUrl,
        auth: ApiAuth,
    ) -> FederationResult<SignedApiAnnouncement>;

    async fn shutdown(&self, session: Option<u64>, auth: ApiAuth) -> FederationResult<()>;

    /// Returns the fedimintd version a peer is running
    async fn fedimintd_version(&self, peer_id: PeerId) -> ServerResult<String>;

    /// Fetch the backup statistics from the federation (admin endpoint)
    async fn backup_statistics(&self, auth: ApiAuth) -> FederationResult<BackupStatistics>;

    /// Get the invite code for the federation guardian.
    /// For instance, useful after DKG
    async fn get_invite_code(&self, guardian: PeerId) -> ServerResult<InviteCode>;

    /// Change the password used to encrypt the configs and for guardian
    /// authentication
    async fn change_password(&self, auth: ApiAuth, new_password: &str) -> FederationResult<()>;

    /// Returns the chain ID (bitcoin block hash at height 1) from the
    /// federation
    async fn chain_id(&self) -> FederationResult<ChainId>;
}

pub fn deserialize_outcome<R>(
    outcome: &SerdeOutputOutcome,
    module_decoder: &Decoder,
) -> OutputOutcomeResult<R>
where
    R: OutputOutcome + MaybeSend,
{
    let dyn_outcome = outcome
        .try_into_inner_known_module_kind(module_decoder)
        .map_err(|e| OutputOutcomeError::ResponseDeserialization(e.into()))?;

    let source_instance = dyn_outcome.module_instance_id();

    dyn_outcome.as_any().downcast_ref().cloned().ok_or_else(|| {
        let target_type = std::any::type_name::<R>();
        OutputOutcomeError::ResponseDeserialization(anyhow!(
            "Could not downcast output outcome with instance id {source_instance} to {target_type}"
        ))
    })
}

/// Federation API client
///
/// The core underlying object used to make API requests to a federation.
///
/// It has an `connectors` handle to actually making outgoing connections
/// to given URLs, and knows which peers there are and what URLs to connect to
/// to reach them.
// TODO: As it is currently it mixes a bit the role of connecting to "peers" with
// general purpose outgoing connection. Not a big deal, but might need refactor
// in the future.
#[derive(Clone, Debug)]
pub struct FederationApi {
    /// Map of known URLs to use to connect to peers
    peers: BTreeMap<PeerId, SafeUrl>,
    /// List of peer ids, redundant to avoid collecting all the time
    peers_keys: BTreeSet<PeerId>,
    /// Our own [`PeerId`] to use when making admin apis
    admin_id: Option<PeerId>,
    /// Set when this API is used to communicate with a module
    module_id: Option<ModuleInstanceId>,
    /// Api secret of the federation
    api_secret: Option<String>,
    /// Connection pool
    connection_pool: ConnectionPool<dyn IGuardianConnection>,
}

impl FederationApi {
    pub fn new(
        connectors: ConnectorRegistry,
        peers: BTreeMap<PeerId, SafeUrl>,
        admin_peer_id: Option<PeerId>,
        api_secret: Option<&str>,
    ) -> Self {
        Self {
            peers_keys: peers.keys().copied().collect(),
            peers,
            admin_id: admin_peer_id,
            module_id: None,
            api_secret: api_secret.map(ToOwned::to_owned),
            connection_pool: ConnectionPool::new(connectors),
        }
    }

    async fn get_or_create_connection(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> ServerResult<DynGuaridianConnection> {
        self.connection_pool
            .get_or_create_connection(url, api_secret, |url, api_secret, connectors| async move {
                let conn = connectors
                    .connect_guardian(&url, api_secret.as_deref())
                    .await?;
                Ok(conn)
            })
            .await
    }

    async fn request(
        &self,
        peer: PeerId,
        method: ApiMethod,
        request: ApiRequestErased,
    ) -> ServerResult<Value> {
        trace!(target: LOG_CLIENT_NET_API, %peer, %method, "Api request");
        let url = self
            .peers
            .get(&peer)
            .ok_or_else(|| ServerError::InvalidPeerId { peer_id: peer })?;
        let conn = self
            .get_or_create_connection(url, self.api_secret.as_deref())
            .await
            .context("Failed to connect to peer")
            .map_err(ServerError::Connection)?;

        let method_str = method.to_string();
        let peer_str = peer.to_string();
        let timer = CLIENT_API_REQUEST_DURATION_SECONDS
            .with_label_values(&[&method_str, &peer_str])
            .start_timer_ext();

        let res = conn.request(method.clone(), request).await;

        timer.observe_duration();

        let result_label = if res.is_ok() { "success" } else { "error" }.to_string();
        CLIENT_API_REQUESTS_TOTAL
            .with_label_values(&[&method_str, &peer_str, &result_label])
            .inc();

        trace!(target: LOG_CLIENT_NET_API, ?method, res_ok = res.is_ok(), "Api response");

        res
    }

    /// Get receiver for changes in the active connections
    ///
    /// This allows real-time monitoring of connection status.
    pub fn get_active_connection_receiver(&self) -> watch::Receiver<BTreeSet<SafeUrl>> {
        self.connection_pool.get_active_connection_receiver()
    }
}

impl IModuleFederationApi for FederationApi {}

#[apply(async_trait_maybe_send!)]
impl IRawFederationApi for FederationApi {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.peers_keys
    }

    fn self_peer(&self) -> Option<PeerId> {
        self.admin_id
    }

    fn with_module(&self, id: ModuleInstanceId) -> DynModuleApi {
        FederationApi {
            api_secret: self.api_secret.clone(),
            peers: self.peers.clone(),
            peers_keys: self.peers_keys.clone(),
            admin_id: self.admin_id,
            module_id: Some(id),
            connection_pool: self.connection_pool.clone(),
        }
        .into()
    }

    #[instrument(
        target = LOG_CLIENT_NET_API,
        skip_all,
        fields(
            peer_id = %peer_id,
            method = %method,
            params = %params.params,
        )
    )]
    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> ServerResult<Value> {
        let method = match self.module_id {
            Some(module_id) => ApiMethod::Module(module_id, method.to_string()),
            None => ApiMethod::Core(method.to_string()),
        };

        self.request(peer_id, method, params.clone()).await
    }

    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, bool>> {
        let peers = self.peers.clone();

        WatchStream::new(self.connection_pool.get_active_connection_receiver())
            .map(move |active_urls| {
                peers
                    .iter()
                    .map(|(peer_id, url)| (*peer_id, active_urls.contains(url)))
                    .collect()
            })
            .boxed()
    }
    async fn wait_for_initialized_connections(&self) {
        self.connection_pool
            .wait_for_initialized_connections()
            .await;
    }
}

/// The status of a server, including how it views its peers
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyFederationStatus {
    pub session_count: u64,
    pub status_by_peer: HashMap<PeerId, LegacyPeerStatus>,
    pub peers_online: u64,
    pub peers_offline: u64,
    /// This should always be 0 if everything is okay, so a monitoring tool
    /// should generate an alert if this is not the case.
    pub peers_flagged: u64,
    pub scheduled_shutdown: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyPeerStatus {
    pub last_contribution: Option<u64>,
    pub connection_status: LegacyP2PConnectionStatus,
    /// Indicates that this peer needs attention from the operator since
    /// it has not contributed to the consensus in a long time
    pub flagged: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyP2PConnectionStatus {
    #[default]
    Disconnected,
    Connected,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StatusResponse {
    pub server: ServerStatusLegacy,
    pub federation: Option<LegacyFederationStatus>,
}

#[cfg(test)]
mod tests;
