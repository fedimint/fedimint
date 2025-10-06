mod error;
pub mod global_api;
mod iroh;
pub mod net;

use core::{fmt, panic};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::iter::once;
use std::pin::Pin;
use std::result;
use std::sync::Arc;

use anyhow::{Context, anyhow};
#[cfg(all(feature = "tor", not(target_family = "wasm")))]
use arti_client::{TorAddr, TorClient, TorClientConfig};
use async_channel::bounded;
use async_trait::async_trait;
use base64::Engine as _;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1;
pub use error::{FederationError, OutputOutcomeError, PeerError};
use fedimint_core::admin_client::{
    GuardianConfigBackup, PeerServerParamsLegacy, ServerStatusLegacy, SetupStatus,
};
use fedimint_core::backup::{BackupStatistics, ClientBackupSnapshot};
use fedimint_core::core::backup::SignedBackupRequest;
use fedimint_core::core::{Decoder, DynOutputOutcome, ModuleInstanceId, OutputOutcome};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::{
    FM_IROH_DNS_ENV, FM_WS_API_CONNECT_OVERRIDES_ENV, parse_kv_list_from_env,
};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::audit::AuditSummary;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{
    ApiAuth, ApiMethod, ApiRequestErased, ApiVersion, SerdeModuleEncoding,
};
use fedimint_core::net::api_announcement::SignedApiAnnouncement;
#[cfg(not(target_family = "wasm"))]
use fedimint_core::rustls::install_crypto_provider;
use fedimint_core::session_outcome::{SessionOutcome, SessionStatus};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::transaction::{Transaction, TransactionSubmissionOutcome};
use fedimint_core::util::backoff_util::api_networking_backoff;
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_core::{
    NumPeersExt, PeerId, TransactionId, apply, async_trait_maybe_send, dyn_newtype_define, util,
};
use fedimint_logging::{LOG_CLIENT_NET_API, LOG_NET_API, LOG_NET_WS};
use futures::channel::oneshot;
use futures::future::pending;
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use global_api::with_cache::GlobalFederationApiWithCache;
use jsonrpsee_core::DeserializeOwned;
use jsonrpsee_core::client::ClientT;
pub use jsonrpsee_core::client::Error as JsonRpcClientError;
use jsonrpsee_types::ErrorCode;
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{CustomCertStore, HeaderMap, HeaderValue};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::OnceCell;
#[cfg(not(target_family = "wasm"))]
use tokio_rustls::rustls::RootCertStore;
#[cfg(all(feature = "tor", not(target_family = "wasm")))]
use tokio_rustls::{TlsConnector, rustls::ClientConfig as TlsClientConfig};
use tracing::{Instrument, debug, instrument, trace, trace_span, warn};

use crate::query::{QueryStep, QueryStrategy, ThresholdConsensus};

pub const VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2: ApiVersion = ApiVersion::new(0, 5);

pub const VERSION_THAT_INTRODUCED_GET_SESSION_STATUS: ApiVersion =
    ApiVersion { major: 0, minor: 1 };

pub type PeerResult<T> = Result<T, PeerError>;
pub type JsonRpcResult<T> = Result<T, JsonRpcClientError>;
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
    ) -> PeerResult<Value>;

    fn connector(&self) -> &DynClientConnector;
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
    ) -> PeerResult<Ret>
    where
        Ret: DeserializeOwned,
    {
        self.request_raw(peer, &method, &params)
            .await
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| PeerError::ResponseDeserialization(e.into()))
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
                serde_json::from_value(v).map_err(|e| PeerError::ResponseDeserialization(e.into()))
            })
            .map_err(|e| error::FederationError::new_one_peer(peer_id, method, params, e))
    }

    /// Make an aggregate request to federation, using `strategy` to logically
    /// merge the responses.
    #[instrument(target = LOG_NET_API, skip_all, fields(method=method))]
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
                    warn!("Query strategy returned non-retryable failure for peer {peer}: {e}");
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
    pub async fn new_admin(
        peer: PeerId,
        url: SafeUrl,
        api_secret: &Option<String>,
        iroh_enable_dht: bool,
        iroh_enable_next: bool,
    ) -> anyhow::Result<DynGlobalApi> {
        let connector =
            make_admin_connector(peer, url, api_secret, iroh_enable_dht, iroh_enable_next).await?;
        Ok(
            GlobalFederationApiWithCache::new(ReconnectFederationApi::new(connector, Some(peer)))
                .into(),
        )
    }

    pub fn new(connector: DynClientConnector) -> anyhow::Result<Self> {
        Ok(GlobalFederationApiWithCache::new(ReconnectFederationApi::new(connector, None)).into())
    }
    // FIXME: (@leonardo) Should we have the option to do DKG and config related
    // actions through Tor ? Should we add the `Connector` choice to
    // ConfigParams then ?
    pub async fn from_setup_endpoint(
        url: SafeUrl,
        api_secret: &Option<String>,
        iroh_enable_dht: bool,
        iroh_enable_next: bool,
    ) -> anyhow::Result<Self> {
        // PeerIds are used only for informational purposes, but just in case, make a
        // big number so it stands out

        Self::new_admin(
            PeerId::from(1024),
            url,
            api_secret,
            iroh_enable_dht,
            iroh_enable_next,
        )
        .await
    }

    pub async fn from_endpoints(
        peers: impl IntoIterator<Item = (PeerId, SafeUrl)>,
        api_secret: &Option<String>,
        iroh_enable_dht: bool,
        iroh_enable_next: bool,
    ) -> anyhow::Result<Self> {
        let connector =
            make_connector(peers, api_secret, iroh_enable_dht, iroh_enable_next).await?;
        Ok(GlobalFederationApiWithCache::new(ReconnectFederationApi::new(connector, None)).into())
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

    /// During config gen, used for an API-to-API call that adds a peer's server
    /// connection info to the leader.
    ///
    /// Note this call will fail until the leader has their API running and has
    /// `set_server_connections` so clients should retry.
    ///
    /// This call is not authenticated because it's guardian-to-guardian
    async fn add_config_gen_peer(&self, peer: PeerServerParamsLegacy) -> FederationResult<()>;

    /// During config gen, gets all the server connections we've received from
    /// peers using `add_config_gen_peer`
    ///
    /// Could be called on the leader, so it's not authenticated
    async fn get_config_gen_peers(&self) -> FederationResult<Vec<PeerServerParamsLegacy>>;

    /// Runs DKG, can only be called once after configs have been generated in
    /// `get_consensus_config_gen_params`.  If DKG fails this returns a 500
    /// error and config gen must be restarted.
    async fn start_dkg(&self, auth: ApiAuth) -> FederationResult<()>;

    /// After DKG, returns the hash of the consensus config tweaked with our id.
    /// We need to share this with all other peers to complete verification.
    async fn get_verify_config_hash(
        &self,
        auth: ApiAuth,
    ) -> FederationResult<BTreeMap<PeerId, sha256::Hash>>;

    /// Updates local state and notify leader that we have verified configs.
    /// This allows for a synchronization point, before we start consensus.
    async fn verified_configs(
        &self,
        auth: ApiAuth,
    ) -> FederationResult<BTreeMap<PeerId, sha256::Hash>>;

    /// Reads the configs from the disk, starts the consensus server, and shuts
    /// down the config gen API to start the Fedimint API
    ///
    /// Clients may receive an error due to forced shutdown, should call the
    /// `server_status` to see if consensus has started.
    async fn start_consensus(&self, auth: ApiAuth) -> FederationResult<()>;

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
    ) -> PeerResult<BTreeMap<PeerId, SignedApiAnnouncement>>;

    async fn sign_api_announcement(
        &self,
        api_url: SafeUrl,
        auth: ApiAuth,
    ) -> FederationResult<SignedApiAnnouncement>;

    async fn shutdown(&self, session: Option<u64>, auth: ApiAuth) -> FederationResult<()>;

    /// Returns the fedimintd version a peer is running
    async fn fedimintd_version(&self, peer_id: PeerId) -> PeerResult<String>;

    /// Fetch the backup statistics from the federation (admin endpoint)
    async fn backup_statistics(&self, auth: ApiAuth) -> FederationResult<BackupStatistics>;

    /// Get the invite code for the federation guardian.
    /// For instance, useful after DKG
    async fn get_invite_code(&self, guardian: PeerId) -> PeerResult<InviteCode>;

    /// Change the password used to encrypt the configs and for guardian
    /// authentication
    async fn change_password(&self, auth: ApiAuth, new_password: &str) -> FederationResult<()>;
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

#[derive(Debug, Clone)]
pub struct WebsocketConnector {
    peers: BTreeMap<PeerId, SafeUrl>,
    api_secret: Option<String>,

    /// List of overrides to use when attempting to connect to given
    /// `PeerId`
    ///
    /// This is useful for testing, or forcing non-default network
    /// connectivity.
    pub connection_overrides: BTreeMap<PeerId, SafeUrl>,

    /// Connection pool for websocket connections
    #[allow(clippy::type_complexity)]
    connections: Arc<tokio::sync::Mutex<HashMap<PeerId, Arc<OnceCell<Arc<WsClient>>>>>>,
}

impl WebsocketConnector {
    fn new(peers: BTreeMap<PeerId, SafeUrl>, api_secret: Option<String>) -> anyhow::Result<Self> {
        let mut s = Self::new_no_overrides(peers, api_secret);

        for (k, v) in parse_kv_list_from_env::<_, SafeUrl>(FM_WS_API_CONNECT_OVERRIDES_ENV)? {
            s = s.with_connection_override(k, v);
        }

        Ok(s)
    }
    pub fn with_connection_override(mut self, peer_id: PeerId, url: SafeUrl) -> Self {
        self.connection_overrides.insert(peer_id, url);
        self
    }
    pub fn new_no_overrides(peers: BTreeMap<PeerId, SafeUrl>, api_secret: Option<String>) -> Self {
        Self {
            peers,
            api_secret,
            connection_overrides: BTreeMap::default(),
            connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    async fn get_or_create_connection(&self, peer_id: PeerId) -> PeerResult<Arc<WsClient>> {
        let mut pool_lock = self.connections.lock().await;

        let entry_arc = pool_lock
            .entry(peer_id)
            .and_modify(|entry_arc| {
                // Check if existing connection is disconnected and remove it
                if let Some(existing_conn) = entry_arc.get() {
                    if !existing_conn.is_connected() {
                        trace!(target: LOG_NET_WS, %peer_id, "Existing connection is disconnected, removing from pool");
                        *entry_arc = Arc::new(OnceCell::new());
                    }
                }
            })
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();

        // Drop the pool lock so other connections can work in parallel
        drop(pool_lock);

        let conn = entry_arc
            .get_or_try_init(|| async {
                trace!(target: LOG_NET_WS, %peer_id, "Creating new websocket connection");
                let api_endpoint = match self.connection_overrides.get(&peer_id) {
                    Some(url) => {
                        trace!(target: LOG_NET_WS, %peer_id, "Using a connectivity override for connection");
                        url
                    }
                    None => self.peers.get(&peer_id).ok_or_else(|| {
                        PeerError::InternalClientError(anyhow!("Invalid peer_id: {peer_id}"))
                    })?,
                };

                #[cfg(not(target_family = "wasm"))]
                let mut client = {
                    install_crypto_provider().await;
                    let webpki_roots = webpki_roots::TLS_SERVER_ROOTS.iter().cloned();
                    let mut root_certs = RootCertStore::empty();
                    root_certs.extend(webpki_roots);

                    let tls_cfg = CustomCertStore::builder()
                        .with_root_certificates(root_certs)
                        .with_no_client_auth();

                    WsClientBuilder::default()
                        .max_concurrent_requests(u16::MAX as usize)
                        .with_custom_cert_store(tls_cfg)
                };

                #[cfg(target_family = "wasm")]
                let client = WsClientBuilder::default().max_concurrent_requests(u16::MAX as usize);

                if let Some(api_secret) = &self.api_secret {
                    #[cfg(not(target_family = "wasm"))]
                    {
                        // on native platforms, jsonrpsee-client ignores `user:pass@...` in the Url,
                        // but we can set up the headers manually
                        let mut headers = HeaderMap::new();

                        let auth = base64::engine::general_purpose::STANDARD
                            .encode(format!("fedimint:{api_secret}"));

                        headers.insert(
                            "Authorization",
                            HeaderValue::from_str(&format!("Basic {auth}")).expect("Can't fail"),
                        );

                        client = client.set_headers(headers);
                    }
                    #[cfg(target_family = "wasm")]
                    {
                        // on wasm, url will be handled by the browser, which should take care of
                        // `user:pass@...`
                        let mut url = api_endpoint.clone();
                        url.set_username("fedimint")
                            .map_err(|_| PeerError::InvalidEndpoint(anyhow!("invalid username")))?;
                        url.set_password(Some(&api_secret))
                            .map_err(|_| PeerError::InvalidEndpoint(anyhow!("invalid secret")))?;

                        let client = client
                            .build(url.as_str())
                            .await
                            .map_err(|err| PeerError::InternalClientError(err.into()))?;

                        return Ok(Arc::new(client));
                    }
                }

                let client = client
                    .build(api_endpoint.as_str())
                    .await
                    .map_err(|err| PeerError::InternalClientError(err.into()))?;

                Ok(Arc::new(client))
            })
            .await?;

        trace!(target: LOG_NET_WS, %peer_id, "Using websocket connection");
        Ok(conn.clone())
    }
}

#[async_trait]
impl IClientConnector for WebsocketConnector {
    fn peers(&self) -> BTreeSet<PeerId> {
        self.peers.keys().copied().collect()
    }

    async fn connect(&self, peer_id: PeerId) -> PeerResult<DynClientConnection> {
        let client = self.get_or_create_connection(peer_id).await?;
        Ok(client.into_dyn())
    }
}

#[cfg(all(feature = "tor", not(target_family = "wasm")))]
#[derive(Debug, Clone)]
pub struct TorConnector {
    peers: BTreeMap<PeerId, SafeUrl>,
    api_secret: Option<String>,
}

#[cfg(all(feature = "tor", not(target_family = "wasm")))]
impl TorConnector {
    pub fn new(peers: BTreeMap<PeerId, SafeUrl>, api_secret: Option<String>) -> Self {
        Self { peers, api_secret }
    }
}

#[cfg(all(feature = "tor", not(target_family = "wasm")))]
#[async_trait]
impl IClientConnector for TorConnector {
    fn peers(&self) -> BTreeSet<PeerId> {
        self.peers.keys().copied().collect()
    }

    #[allow(clippy::too_many_lines)]
    async fn connect(&self, peer_id: PeerId) -> PeerResult<DynClientConnection> {
        let api_endpoint = self
            .peers
            .get(&peer_id)
            .ok_or_else(|| PeerError::InternalClientError(anyhow!("Invalid peer_id: {peer_id}")))?;

        let tor_config = TorClientConfig::default();
        let tor_client = TorClient::create_bootstrapped(tor_config)
            .await
            .map_err(|err| PeerError::InternalClientError(err.into()))?
            .isolated_client();

        debug!("Successfully created and bootstrapped the `TorClient`, for given `TorConfig`.");

        // TODO: (@leonardo) should we implement our `IntoTorAddr` for `SafeUrl`
        // instead?
        let addr = (
            api_endpoint
                .host_str()
                .ok_or_else(|| PeerError::InvalidEndpoint(anyhow!("Expected host str")))?,
            api_endpoint
                .port_or_known_default()
                .ok_or_else(|| PeerError::InvalidEndpoint(anyhow!("Expected port number")))?,
        );
        let tor_addr = TorAddr::from(addr).map_err(|e| {
            PeerError::InvalidEndpoint(anyhow!("Invalid endpoint addr: {addr:?}: {e:#}"))
        })?;

        let tor_addr_clone = tor_addr.clone();

        debug!(
            ?tor_addr,
            ?addr,
            "Successfully created `TorAddr` for given address (i.e. host and port)"
        );

        // TODO: It can be updated to use `is_onion_address()` implementation,
        // once https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2214 lands.
        let anonymized_stream = if api_endpoint.is_onion_address() {
            let mut stream_prefs = arti_client::StreamPrefs::default();
            stream_prefs.connect_to_onion_services(arti_client::config::BoolOrAuto::Explicit(true));

            let anonymized_stream = tor_client
                .connect_with_prefs(tor_addr, &stream_prefs)
                .await
                .map_err(|e| PeerError::Connection(e.into()))?;

            debug!(
                ?tor_addr_clone,
                "Successfully connected to onion address `TorAddr`, and established an anonymized `DataStream`"
            );
            anonymized_stream
        } else {
            let anonymized_stream = tor_client
                .connect(tor_addr)
                .await
                .map_err(|e| PeerError::Connection(e.into()))?;

            debug!(
                ?tor_addr_clone,
                "Successfully connected to `Hostname`or `Ip` `TorAddr`, and established an anonymized `DataStream`"
            );
            anonymized_stream
        };

        let is_tls = match api_endpoint.scheme() {
            "wss" => true,
            "ws" => false,
            unexpected_scheme => {
                return Err(PeerError::InvalidEndpoint(anyhow!(
                    "Unsupported scheme: {unexpected_scheme}"
                )));
            }
        };

        let tls_connector = if is_tls {
            let webpki_roots = webpki_roots::TLS_SERVER_ROOTS.iter().cloned();
            let mut root_certs = RootCertStore::empty();
            root_certs.extend(webpki_roots);

            let tls_config = TlsClientConfig::builder()
                .with_root_certificates(root_certs)
                .with_no_client_auth();
            let tls_connector = TlsConnector::from(Arc::new(tls_config));
            Some(tls_connector)
        } else {
            None
        };

        let mut ws_client_builder =
            WsClientBuilder::default().max_concurrent_requests(u16::MAX as usize);

        if let Some(api_secret) = &self.api_secret {
            // on native platforms, jsonrpsee-client ignores `user:pass@...` in the Url,
            // but we can set up the headers manually
            let mut headers = HeaderMap::new();

            let auth =
                base64::engine::general_purpose::STANDARD.encode(format!("fedimint:{api_secret}"));

            headers.insert(
                "Authorization",
                HeaderValue::from_str(&format!("Basic {auth}")).expect("Can't fail"),
            );

            ws_client_builder = ws_client_builder.set_headers(headers);
        }

        match tls_connector {
            None => {
                let client = ws_client_builder
                    .build_with_stream(api_endpoint.as_str(), anonymized_stream)
                    .await
                    .map_err(|e| PeerError::Connection(e.into()))?;

                Ok(client.into_dyn())
            }
            Some(tls_connector) => {
                let host = api_endpoint
                    .host_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| PeerError::InvalidEndpoint(anyhow!("Invalid host str")))?;

                // FIXME: (@leonardo) Is this leaking any data ? Should investigate it further
                // if it's really needed.
                let server_name = rustls_pki_types::ServerName::try_from(host)
                    .map_err(|e| PeerError::InvalidEndpoint(e.into()))?;

                let anonymized_tls_stream = tls_connector
                    .connect(server_name, anonymized_stream)
                    .await
                    .map_err(|e| PeerError::Connection(e.into()))?;

                let client = ws_client_builder
                    .build_with_stream(api_endpoint.as_str(), anonymized_tls_stream)
                    .await
                    .map_err(|e| PeerError::Connection(e.into()))?;

                Ok(client.into_dyn())
            }
        }
    }
}

fn jsonrpc_error_to_peer_error(jsonrpc_error: JsonRpcClientError) -> PeerError {
    match jsonrpc_error {
        JsonRpcClientError::Call(error_object) => {
            let error = anyhow!(error_object.message().to_owned());
            match ErrorCode::from(error_object.code()) {
                ErrorCode::ParseError | ErrorCode::OversizedRequest | ErrorCode::InvalidRequest => {
                    PeerError::InvalidRequest(error)
                }
                ErrorCode::MethodNotFound => PeerError::InvalidRpcId(error),
                ErrorCode::InvalidParams => PeerError::InvalidRequest(error),
                ErrorCode::InternalError | ErrorCode::ServerIsBusy | ErrorCode::ServerError(_) => {
                    PeerError::ServerError(error)
                }
            }
        }
        JsonRpcClientError::Transport(error) => PeerError::Transport(anyhow!(error)),
        JsonRpcClientError::RestartNeeded(arc) => PeerError::Transport(anyhow!(arc)),
        JsonRpcClientError::ParseError(error) => PeerError::InvalidResponse(anyhow!(error)),
        JsonRpcClientError::InvalidSubscriptionId => {
            PeerError::Transport(anyhow!("Invalid subscription id"))
        }
        JsonRpcClientError::InvalidRequestId(invalid_request_id) => {
            PeerError::InvalidRequest(anyhow!(invalid_request_id))
        }
        JsonRpcClientError::RequestTimeout => PeerError::Transport(anyhow!("Request timeout")),
        JsonRpcClientError::Custom(e) => PeerError::Transport(anyhow!(e)),
        JsonRpcClientError::HttpNotImplemented => {
            PeerError::ServerError(anyhow!("Http not implemented"))
        }
        JsonRpcClientError::EmptyBatchRequest(empty_batch_request) => {
            PeerError::InvalidRequest(anyhow!(empty_batch_request))
        }
        JsonRpcClientError::RegisterMethod(register_method_error) => {
            PeerError::InvalidResponse(anyhow!(register_method_error))
        }
    }
}

#[async_trait]
impl IClientConnection for WsClient {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> PeerResult<Value> {
        let method = match method {
            ApiMethod::Core(method) => method,
            ApiMethod::Module(module_id, method) => format!("module_{module_id}_{method}"),
        };

        Ok(ClientT::request(self, &method, [request.to_json()])
            .await
            .map_err(jsonrpc_error_to_peer_error)?)
    }

    async fn await_disconnection(&self) {
        self.on_disconnect().await;
    }
}

#[async_trait]
impl IClientConnection for Arc<WsClient> {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> PeerResult<Value> {
        let method = match method {
            ApiMethod::Core(method) => method,
            ApiMethod::Module(module_id, method) => format!("module_{module_id}_{method}"),
        };

        Ok(
            ClientT::request(self.as_ref(), &method, [request.to_json()])
                .await
                .map_err(jsonrpc_error_to_peer_error)?,
        )
    }

    async fn await_disconnection(&self) {
        self.on_disconnect().await;
    }
}

pub type DynClientConnector = Arc<dyn IClientConnector>;

/// Allows to connect to peers. Connections are request based and should be
/// authenticated and encrypted for production deployments.
#[async_trait]
pub trait IClientConnector: Send + Sync + 'static + fmt::Debug {
    fn peers(&self) -> BTreeSet<PeerId>;

    async fn connect(&self, peer: PeerId) -> PeerResult<DynClientConnection>;

    fn into_dyn(self) -> DynClientConnector
    where
        Self: Sized,
    {
        Arc::new(self)
    }

    fn is_admin(&self) -> bool {
        self.peers().len() == 1
    }
}

pub type DynClientConnection = Arc<dyn IClientConnection>;

#[async_trait]
pub trait IClientConnection: Debug + Send + Sync + 'static {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> PeerResult<Value>;

    async fn await_disconnection(&self);

    fn into_dyn(self) -> DynClientConnection
    where
        Self: Sized,
    {
        Arc::new(self)
    }
}

#[derive(Clone, Debug)]
pub struct ReconnectFederationApi {
    connector: DynClientConnector,
    peers: BTreeSet<PeerId>,
    admin_id: Option<PeerId>,
    module_id: Option<ModuleInstanceId>,
    connections: ReconnectClientConnections,
}

impl ReconnectFederationApi {
    pub fn new(connector: DynClientConnector, admin_peer_id: Option<PeerId>) -> Self {
        Self {
            peers: connector.peers(),
            admin_id: admin_peer_id,
            module_id: None,
            connections: ReconnectClientConnections::new(&connector),
            connector,
        }
    }

    pub fn new_admin(connector: DynClientConnector, peer: PeerId) -> Self {
        Self::new(connector, Some(peer))
    }
}

impl IModuleFederationApi for ReconnectFederationApi {}

#[apply(async_trait_maybe_send!)]
impl IRawFederationApi for ReconnectFederationApi {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.peers
    }

    fn self_peer(&self) -> Option<PeerId> {
        self.admin_id
    }

    fn with_module(&self, id: ModuleInstanceId) -> DynModuleApi {
        ReconnectFederationApi {
            connector: self.connector.clone(),
            peers: self.peers.clone(),
            admin_id: self.admin_id,
            module_id: Some(id),
            connections: self.connections.clone(),
        }
        .into()
    }

    #[instrument(
        target = LOG_NET_API,
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
    ) -> PeerResult<Value> {
        let method = match self.module_id {
            Some(module_id) => ApiMethod::Module(module_id, method.to_string()),
            None => ApiMethod::Core(method.to_string()),
        };

        self.connections
            .request(peer_id, method, params.clone())
            .await
    }
    fn connector(&self) -> &DynClientConnector {
        &self.connector
    }
}

#[derive(Clone, Debug)]
pub struct ReconnectClientConnections {
    connections: BTreeMap<PeerId, ClientConnection>,
}

impl ReconnectClientConnections {
    pub fn new(connector: &DynClientConnector) -> Self {
        ReconnectClientConnections {
            connections: connector
                .peers()
                .into_iter()
                .map(|peer| (peer, ClientConnection::new(peer, connector.clone())))
                .collect(),
        }
    }

    async fn request(
        &self,
        peer: PeerId,
        method: ApiMethod,
        request: ApiRequestErased,
    ) -> PeerResult<Value> {
        trace!(target: LOG_NET_API, %method, "Api request");
        let res = self
            .connections
            .get(&peer)
            .ok_or_else(|| PeerError::InvalidPeerId { peer_id: peer })?
            .connection()
            .await
            .context("Failed to connect to peer")
            .map_err(PeerError::Connection)?
            .request(method.clone(), request)
            .await;

        trace!(target: LOG_NET_API, ?method, res_ok = res.is_ok(), "Api response");

        res
    }
}

#[derive(Clone, Debug)]
struct ClientConnection {
    sender: async_channel::Sender<oneshot::Sender<DynClientConnection>>,
}

impl ClientConnection {
    fn new(peer: PeerId, connector: DynClientConnector) -> ClientConnection {
        let (sender, receiver) = bounded::<oneshot::Sender<DynClientConnection>>(1024);

        fedimint_core::task::spawn(
            "peer-api-connection",
            async move {
                let mut backoff = api_networking_backoff();

                while let Ok(sender) = receiver.recv().await {
                    let mut senders = vec![sender];

                    // Drain the queue, so we everyone that already joined fail or succeed
                    // together.
                    while let Ok(sender) = receiver.try_recv() {
                        senders.push(sender);
                    }

                    match connector.connect(peer).await {
                        Ok(connection) => {
                            trace!(target: LOG_CLIENT_NET_API, "Connected to peer api");

                            for sender in senders {
                                sender.send(connection.clone()).ok();
                            }

                            loop {
                                tokio::select! {
                                    sender = receiver.recv() => {
                                        match sender.ok() {
                                            Some(sender) => sender.send(connection.clone()).ok(),
                                            None => break,
                                        };
                                    }
                                    () = connection.await_disconnection() => break,
                                }
                            }

                            trace!(target: LOG_CLIENT_NET_API, "Disconnected from peer api");

                            backoff = api_networking_backoff();
                        }
                        Err(e) => {
                            trace!(target: LOG_CLIENT_NET_API, "Failed to connect to peer api {e}");

                            fedimint_core::task::sleep(
                                backoff.next().expect("No limit to the number of retries"),
                            )
                            .await;
                        }
                    }
                }

                trace!(target: LOG_CLIENT_NET_API, "Shutting down peer api connection task");
            }
            .instrument(trace_span!("peer-api-connection", ?peer)),
        );

        ClientConnection { sender }
    }

    async fn connection(&self) -> Option<DynClientConnection> {
        let (sender, receiver) = oneshot::channel();

        self.sender
            .send(sender)
            .await
            .inspect_err(|err| {
                warn!(
                    target: LOG_CLIENT_NET_API,
                    err = %err.fmt_compact(),
                    "Api connection request channel closed unexpectedly"
                );
            })
            .ok()?;

        receiver.await.ok()
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

pub async fn make_admin_connector(
    admin_peer_id: PeerId,
    url: SafeUrl,
    api_secret: &Option<String>,
    iroh_enable_dht: bool,
    iroh_enable_next: bool,
) -> anyhow::Result<DynClientConnector> {
    make_connector(
        once((admin_peer_id, url)),
        api_secret,
        iroh_enable_dht,
        iroh_enable_next,
    )
    .await
}

pub async fn make_connector(
    peers: impl IntoIterator<Item = (PeerId, SafeUrl)>,
    api_secret: &Option<String>,
    iroh_enable_dht: bool,
    iroh_enable_next: bool,
) -> anyhow::Result<DynClientConnector> {
    let peers = peers.into_iter().collect::<BTreeMap<PeerId, SafeUrl>>();

    let scheme = peers
        .values()
        .next()
        .expect("Federation api has been initialized with no peers")
        .scheme();

    Ok(match scheme {
        "ws" | "wss" => WebsocketConnector::new(peers, api_secret.clone())?.into_dyn(),
        #[cfg(all(feature = "tor", not(target_family = "wasm")))]
        "tor" => TorConnector::new(peers, api_secret.clone()).into_dyn(),
        "iroh" => {
            let iroh_dns = std::env::var(FM_IROH_DNS_ENV)
                .ok()
                .and_then(|dns| dns.parse().ok());
            iroh::IrohConnector::new(peers, iroh_dns, iroh_enable_dht, iroh_enable_next)
                .await?
                .into_dyn()
        }
        scheme => anyhow::bail!("Unsupported connector scheme: {scheme}"),
    })
}

#[cfg(test)]
mod tests;
