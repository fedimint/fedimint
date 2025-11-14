mod error;
pub mod global_api;
pub mod iroh;
pub mod net;
#[cfg(all(feature = "tor", not(target_family = "wasm")))]
pub mod tor;
pub mod ws;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::future::pending;
use std::pin::Pin;
use std::result;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use async_trait::async_trait;
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
use fedimint_core::envs::{FM_WS_API_CONNECT_OVERRIDES_ENV, parse_kv_list_from_env};
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
use fedimint_core::util::backoff_util::{FibonacciBackoff, api_networking_backoff, custom_backoff};
use fedimint_core::util::{FmtCompact as _, FmtCompactAnyhow as _, SafeUrl};
use fedimint_core::{
    NumPeersExt, PeerId, TransactionId, apply, async_trait_maybe_send, dyn_newtype_define, util,
};
use fedimint_logging::{LOG_CLIENT_NET_API, LOG_NET, LOG_NET_API};
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use global_api::with_cache::GlobalFederationApiWithCache;
use jsonrpsee_core::DeserializeOwned;
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::OnceCell;
use tracing::{debug, instrument, trace, warn};

use crate::api;
use crate::api::ws::WebsocketConnector;
use crate::query::{QueryStep, QueryStrategy, ThresholdConsensus};

/// Type for connector initialization functions
type ConnectorInitFn = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = anyhow::Result<DynConnector>> + Send>> + Send + Sync,
>;

pub const VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2: ApiVersion = ApiVersion::new(0, 5);

pub const VERSION_THAT_INTRODUCED_GET_SESSION_STATUS: ApiVersion =
    ApiVersion { major: 0, minor: 1 };

pub type PeerResult<T> = Result<T, PeerError>;
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

/// Builder for [`ConnectorRegistry`]
///
/// See [`ConnectorRegistry::build_from_client_env`] and similar
/// to create.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // Shut up, Clippy
pub struct ConnectorRegistryBuilder {
    /// List of overrides to use when attempting to connect to given url
    ///
    /// This is useful for testing, or forcing non-default network
    /// connectivity.
    connection_overrides: BTreeMap<SafeUrl, SafeUrl>,

    /// Enable Iroh endpoints at all?
    iroh_enable: bool,
    /// Override the Iroh DNS server to use
    iroh_dns: Option<SafeUrl>,
    /// Should start the "next/unstable" Iroh stack
    iroh_next: bool,
    /// Enable Pkarr DHT discovery
    iroh_pkarr_dht: bool,

    /// Enable Websocket API handling at all?
    ws_enable: bool,
    ws_force_tor: bool,
}

impl ConnectorRegistryBuilder {
    #[allow(clippy::unused_async)] // Leave room for async in the future
    pub async fn bind(self) -> anyhow::Result<ConnectorRegistry> {
        // Create initialization functions for each connector type
        let mut connectors_lazy: BTreeMap<String, (ConnectorInitFn, OnceCell<DynConnector>)> =
            BTreeMap::new();

        // WS connector init function
        let builder_ws = self.clone();
        let ws_connector_init = Arc::new(move || {
            let builder = builder_ws.clone();
            Box::pin(async move { builder.build_ws_connector().await })
                as Pin<Box<dyn Future<Output = anyhow::Result<DynConnector>> + Send>>
        });
        connectors_lazy.insert("ws".into(), (ws_connector_init.clone(), OnceCell::new()));
        connectors_lazy.insert("wss".into(), (ws_connector_init.clone(), OnceCell::new()));

        // Iroh connector init function
        let builder_iroh = self.clone();
        connectors_lazy.insert(
            "iroh".into(),
            (
                Arc::new(move || {
                    let builder = builder_iroh.clone();
                    Box::pin(async move { builder.build_iroh_connector().await })
                        as Pin<Box<dyn Future<Output = anyhow::Result<DynConnector>> + Send>>
                }),
                OnceCell::new(),
            ),
        );

        Ok(ConnectorRegistry {
            connectors_lazy,
            connection_overrides: self.connection_overrides,
        })
    }

    pub async fn build_iroh_connector(&self) -> anyhow::Result<DynConnector> {
        if !self.iroh_enable {
            bail!("Iroh connector not enabled");
        }
        Ok(Arc::new(
            api::iroh::IrohConnector::new(
                self.iroh_dns.clone(),
                self.iroh_pkarr_dht,
                self.iroh_next,
            )
            .await?,
        ) as DynConnector)
    }

    pub async fn build_ws_connector(&self) -> anyhow::Result<DynConnector> {
        if !self.ws_enable {
            bail!("Websocket connector not enabled");
        }

        match self.ws_force_tor {
            #[cfg(all(feature = "tor", not(target_family = "wasm")))]
            true => {
                use crate::api::tor::TorConnector;

                Ok(Arc::new(TorConnector::bootstrap().await?) as DynConnector)
            }

            false => Ok(Arc::new(WebsocketConnector::new()) as DynConnector),
            #[allow(unreachable_patterns)]
            _ => bail!("Tor requested, but not support not compiled in"),
        }
    }

    pub fn iroh_pkarr_dht(self, enable: bool) -> Self {
        Self {
            iroh_pkarr_dht: enable,
            ..self
        }
    }

    pub fn iroh_next(self, enable: bool) -> Self {
        Self {
            iroh_next: enable,
            ..self
        }
    }

    pub fn ws_force_tor(self, enable: bool) -> Self {
        Self {
            ws_force_tor: enable,
            ..self
        }
    }

    pub fn set_iroh_dns(self, url: SafeUrl) -> Self {
        Self {
            iroh_dns: Some(url),
            ..self
        }
    }

    /// Apply overrides from env variables
    pub fn with_env_var_overrides(mut self) -> anyhow::Result<Self> {
        // TODO: read rest of the env
        for (k, v) in parse_kv_list_from_env::<_, SafeUrl>(FM_WS_API_CONNECT_OVERRIDES_ENV)? {
            self = self.with_connection_override(k, v);
        }

        Ok(Self { ..self })
    }

    pub fn with_connection_override(
        mut self,
        original_url: SafeUrl,
        replacement_url: SafeUrl,
    ) -> Self {
        self.connection_overrides
            .insert(original_url, replacement_url);
        self
    }
}

/// A set of available connectivity protocols a client can use to make
/// network API requests (typically to federation).
///
/// Maps from connection URL schema to [`Connector`] to use to connect to it.
///
/// See [`ConnectorRegistry::build_from_client_env`] and similar
/// to create.
///
/// [`ConnectorRegistry::connect_guardian`] is the main entry point for making
/// mixed-networking stack connection.
///
/// Responsibilities:
#[derive(Clone)]
pub struct ConnectorRegistry {
    connectors_lazy: BTreeMap<String, (ConnectorInitFn, OnceCell<DynConnector>)>,
    /// Connection URL overrides for testing/custom routing
    connection_overrides: BTreeMap<SafeUrl, SafeUrl>,
}

impl fmt::Debug for ConnectorRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectorRegistry")
            .field("connectors_lazy", &self.connectors_lazy.len())
            .field("connection_overrides", &self.connection_overrides)
            .finish()
    }
}

impl ConnectorRegistry {
    /// Create a builder with recommended defaults intended for client-side
    /// usage
    ///
    /// In particular mobile devices are considered.
    pub fn build_from_client_defaults() -> ConnectorRegistryBuilder {
        ConnectorRegistryBuilder {
            iroh_enable: true,
            iroh_dns: None,
            iroh_pkarr_dht: false,
            iroh_next: true,
            ws_enable: true,
            ws_force_tor: false,

            connection_overrides: BTreeMap::default(),
        }
    }

    /// Create a builder with recommended defaults intended for the server-side
    /// usage
    pub fn build_from_server_defaults() -> ConnectorRegistryBuilder {
        ConnectorRegistryBuilder {
            iroh_enable: true,
            iroh_dns: None,
            iroh_pkarr_dht: true,
            iroh_next: true,
            ws_enable: true,
            ws_force_tor: false,

            connection_overrides: BTreeMap::default(),
        }
    }

    /// Create a builder with recommended defaults intended for testing
    /// usage
    pub fn build_from_testing_defaults() -> ConnectorRegistryBuilder {
        ConnectorRegistryBuilder {
            iroh_enable: true,
            iroh_dns: None,
            iroh_pkarr_dht: false,
            iroh_next: false,
            ws_enable: true,
            ws_force_tor: false,

            connection_overrides: BTreeMap::default(),
        }
    }

    /// Like [`Self::build_from_client_defaults`] build will apply
    /// environment-provided overrides.
    pub fn build_from_client_env() -> anyhow::Result<ConnectorRegistryBuilder> {
        let builder = Self::build_from_client_defaults().with_env_var_overrides()?;
        Ok(builder)
    }

    /// Like [`Self::build_from_server_defaults`] build will apply
    /// environment-provided overrides.
    pub fn build_from_server_env() -> anyhow::Result<ConnectorRegistryBuilder> {
        let builder = Self::build_from_server_defaults().with_env_var_overrides()?;
        Ok(builder)
    }

    /// Like [`Self::build_from_testing_defaults`] build will apply
    /// environment-provided overrides.
    pub fn build_from_testing_env() -> anyhow::Result<ConnectorRegistryBuilder> {
        let builder = Self::build_from_testing_defaults().with_env_var_overrides()?;
        Ok(builder)
    }

    /// Connect to a given `url` using matching [`Connector`]
    ///
    /// This is the main function consumed by the downstream use for making
    /// connection.
    pub async fn connect_guardian(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> PeerResult<DynGuaridianConnection> {
        let url = match self.connection_overrides.get(url) {
            Some(replacement) => {
                trace!(
                    target: LOG_NET,
                    original_url = %url,
                    replacement_url = %replacement,
                    "Using a connectivity override for connection"
                );

                replacement
            }
            None => url,
        };

        let connector_key = url.scheme();

        let Some(connector_lazy) = self.connectors_lazy.get(connector_key) else {
            return Err(PeerError::InvalidEndpoint(anyhow!(
                "Unsupported scheme: {}; missing endpoint handler",
                url.scheme()
            )));
        };

        // Clone the init function to use in the async block
        let init_fn = connector_lazy.0.clone();

        connector_lazy
            .1
            .get_or_try_init(|| async move { init_fn().await })
            .await
            .map_err(|e| {
                PeerError::Transport(anyhow!(
                    "Connector failed to initialize: {}",
                    e.fmt_compact_anyhow()
                ))
            })?
            .connect_guardian(url, api_secret)
            .await
    }
}
pub type DynConnector = Arc<dyn Connector>;

#[async_trait]
pub trait Connector: Send + Sync + 'static + fmt::Debug {
    async fn connect_guardian(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> PeerResult<DynGuaridianConnection>;
}

/// A connection from api client to a federation guardian (type erased)
pub type DynGuaridianConnection = Arc<dyn IGuardianConnection>;

/// A connection from api client to a federation guardian
#[async_trait]
pub trait IGuardianConnection: Debug + Send + Sync + 'static {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> PeerResult<Value>;

    fn is_connected(&self) -> bool;

    async fn await_disconnection(&self);

    fn into_dyn(self) -> DynGuaridianConnection
    where
        Self: Sized,
    {
        Arc::new(self)
    }
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
    /// Available connectors which we can make connections
    connectors: ConnectorRegistry,
    /// Map of known URLs to use to connect to peers
    peers: BTreeMap<PeerId, SafeUrl>,
    /// List of peer ids, redundant to avoid collecting all the time
    peers_keys: BTreeSet<PeerId>,
    /// Our own [`PeerId`] to use when making admin apis
    admin_id: Option<PeerId>,
    /// Set when this API is used to communicate with a module
    module_id: Option<ModuleInstanceId>,

    api_secret: Option<String>,

    /// Connection pool
    ///
    /// Every entry in this map will be created on demand and correspond to a
    /// single outgoing connection to a certain URL that is in the process
    /// of being established, or we already established.
    #[allow(clippy::type_complexity)]
    connections: Arc<tokio::sync::Mutex<HashMap<SafeUrl, Arc<ConnectionState>>>>,
}

/// Inner part of [`ConnectionState`] preserving state between attempts to
/// initialize [`ConnectionState::connection`]
#[derive(Debug)]
struct ConnectionStateInner {
    fresh: bool,
    backoff: FibonacciBackoff,
}

#[derive(Debug)]
struct ConnectionState {
    /// Connection we are trying to or already established
    connection: tokio::sync::OnceCell<DynGuaridianConnection>,
    /// State that technically is protected every time by
    /// the serialization of `OnceCell::get_or_try_init`, but
    /// for Rust purposes needs to be locked.
    inner: std::sync::Mutex<ConnectionStateInner>,
}

impl ConnectionState {
    /// Create a new connection state for a first time connection
    fn new_initial() -> Self {
        Self {
            connection: OnceCell::new(),
            inner: std::sync::Mutex::new(ConnectionStateInner {
                fresh: true,
                backoff: custom_backoff(
                    // First time connections start quick
                    Duration::from_millis(5),
                    Duration::from_secs(30),
                    None,
                ),
            }),
        }
    }

    /// Create a new connection state for a connection that already failed, and
    /// is being reset
    fn new_reconnecting() -> Self {
        Self {
            connection: OnceCell::new(),
            inner: std::sync::Mutex::new(ConnectionStateInner {
                // set the attempts to 1, indicating that
                fresh: false,
                backoff: custom_backoff(
                    // Connections after a disconnect start with some minimum delay
                    Duration::from_millis(500),
                    Duration::from_secs(30),
                    None,
                ),
            }),
        }
    }

    /// Record the fact that an attempt to connect is being made, and return
    /// time the caller should wait.
    fn pre_reconnect_delay(&self) -> Duration {
        let mut backoff_locked = self.inner.lock().expect("Locking failed");
        let fresh = backoff_locked.fresh;

        backoff_locked.fresh = false;

        if fresh {
            Duration::default()
        } else {
            backoff_locked.backoff.next().expect("Keeps retrying")
        }
    }
}
impl FederationApi {
    pub fn new(
        connectors: ConnectorRegistry,
        peers: BTreeMap<PeerId, SafeUrl>,
        admin_peer_id: Option<PeerId>,
        api_secret: Option<&str>,
    ) -> Self {
        Self {
            connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peers_keys: peers.keys().copied().collect(),
            peers,
            admin_id: admin_peer_id,
            module_id: None,
            connectors,
            api_secret: api_secret.map(ToOwned::to_owned),
        }
    }

    async fn get_or_create_connection(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> PeerResult<DynGuaridianConnection> {
        let mut pool_locked = self.connections.lock().await;

        let pool_entry_arc = pool_locked
            .entry(url.to_owned())
                        .and_modify(|entry_arc| {
                // Check if existing connection is disconnected and reset the whole entry.
                //
                // This resets the state (like connectivity backoff), which is what we want.
                // Since the (`OnceCell`) was already initialized, it means connection was successfully
                // before, and disconnected afterwards.
                if let Some(existing_conn) = entry_arc.connection.get()
                    && !existing_conn.is_connected(){
                        trace!(target: LOG_NET_API, %url, "Existing connection is disconnected, removing from pool");
                        *entry_arc = Arc::new(ConnectionState::new_reconnecting());
                    }
            })
            .or_insert_with(|| Arc::new(ConnectionState::new_initial()))
            .clone();

        // Drop the pool lock so other connections can work in parallel
        drop(pool_locked);

        let conn = pool_entry_arc
            .connection
            // This serializes all the connection attempts. If one attempt to connect (including
            // waiting for the reconnect backoff) succeeds, all waiting ones will use it. If it
            // fails, any already pending/next will attempt it right afterwards.
            // Nit: if multiple calls are trying to connect to the same host that is offline, it
            // will take some of them multiples of maximum retry delay to actually return with
            // an error. This should be fine in practice and hard to avoid without a lot of
            // complexity.
            .get_or_try_init(|| async {
                let retry_delay = pool_entry_arc.pre_reconnect_delay();
                fedimint_core::runtime::sleep(retry_delay).await;

                let conn = self.connectors.connect_guardian(url, api_secret).await?;

                Ok(conn)
            })
            .await?;

        trace!(target: LOG_NET_API, %url, "Using websocket connection");
        Ok(conn.clone())
    }

    async fn request(
        &self,
        peer: PeerId,
        method: ApiMethod,
        request: ApiRequestErased,
    ) -> PeerResult<Value> {
        trace!(target: LOG_NET_API, %peer, %method, "Api request");
        let url = self
            .peers
            .get(&peer)
            .ok_or_else(|| PeerError::InvalidPeerId { peer_id: peer })?;
        let conn = self
            .get_or_create_connection(url, self.api_secret.as_deref())
            .await
            .context("Failed to connect to peer")
            .map_err(PeerError::Connection)?;
        let res = conn.request(method.clone(), request).await;

        trace!(target: LOG_NET_API, ?method, res_ok = res.is_ok(), "Api response");

        res
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
            connections: self.connections.clone(),
            connectors: self.connectors.clone(),
            peers: self.peers.clone(),
            peers_keys: self.peers_keys.clone(),
            admin_id: self.admin_id,
            module_id: Some(id),
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

        self.request(peer_id, method, params.clone()).await
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
