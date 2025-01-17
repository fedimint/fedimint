use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::iter::once;
use std::pin::Pin;
use std::result;
use std::sync::Arc;

use anyhow::{anyhow, Context};
#[cfg(all(feature = "tor", not(target_family = "wasm")))]
use arti_client::{TorAddr, TorClient, TorClientConfig};
use async_channel::bounded;
use async_trait::async_trait;
use base64::Engine as _;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1;
pub use error::{FederationError, OutputOutcomeError, PeerError};
use fedimint_core::admin_client::{
    ConfigGenConnectionsRequest, ConfigGenParamsRequest, ConfigGenParamsResponse, PeerServerParams,
    ServerStatus,
};
use fedimint_core::backup::ClientBackupSnapshot;
use fedimint_core::core::backup::SignedBackupRequest;
use fedimint_core::core::{Decoder, DynOutputOutcome, ModuleInstanceId, OutputOutcome};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::audit::AuditSummary;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiAuth, ApiRequestErased, ApiVersion, SerdeModuleEncoding};
use fedimint_core::net::api_announcement::SignedApiAnnouncement;
use fedimint_core::session_outcome::{SessionOutcome, SessionStatus};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::transaction::{Transaction, TransactionSubmissionOutcome};
use fedimint_core::util::backoff_util::api_networking_backoff;
use fedimint_core::util::SafeUrl;
use fedimint_core::{
    apply, async_trait_maybe_send, dyn_newtype_define, util, NumPeersExt, PeerId, TransactionId,
};
use fedimint_logging::{LOG_CLIENT_NET_API, LOG_NET_API};
use futures::channel::oneshot;
use futures::future::pending;
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use jsonrpsee_core::client::ClientT;
pub use jsonrpsee_core::client::Error as JsonRpcClientError;
use jsonrpsee_core::DeserializeOwned;
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{CustomCertStore, HeaderMap, HeaderValue};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use net::Connector;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(not(target_family = "wasm"))]
use tokio_rustls::rustls::RootCertStore;
#[cfg(all(feature = "tor", not(target_family = "wasm")))]
use tokio_rustls::{rustls::ClientConfig as TlsClientConfig, TlsConnector};
use tracing::{debug, info, info_span, instrument, warn, Instrument};

use crate::query::{QueryStep, QueryStrategy, ThresholdConsensus};
mod error;
mod global_api;
pub mod net;

pub use global_api::{GlobalFederationApiWithCache, GlobalFederationApiWithCacheExt};

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

    /// PeerId of the Guardian node, if set
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
    ) -> result::Result<Value, JsonRpcClientError>;
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
            .map_err(PeerError::Rpc)
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
            .map_err(PeerError::Rpc)
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
                        peer_errors.insert(peer, PeerError::InvalidResponse(e.to_string()));
                    }
                    QueryStep::Continue => {}
                },
                Err(e) => {
                    e.report_if_important(peer);

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
                        "api-request-{method}-{peer}",
                        api_networking_backoff(),
                        || async {
                            self.request_single_peer(method.clone(), params.clone(), *peer)
                                .await
                                .inspect_err(|e| e.report_if_important(*peer))
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
                                    "api-request-{method}-{peer}",
                                    api_networking_backoff(),
                                    || async {
                                        self.request_single_peer(
                                            method.clone(),
                                            params.clone(),
                                            peer,
                                        )
                                        .await
                                        .inspect_err(|e| e.report_if_important(peer))
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
    pub fn new_admin(
        peer: PeerId,
        url: SafeUrl,
        api_secret: &Option<String>,
        connector: &Connector,
    ) -> DynGlobalApi {
        Self::from_endpoints(once((peer, url)), api_secret, connector, Some(peer))
    }

    // FIXME: (@leonardo) Should we have the option to do DKG and config related
    // actions through Tor ? Should we add the `Connector` choice to
    // ConfigParams then ?
    pub fn from_pre_peer_id_admin_endpoint(url: SafeUrl, api_secret: &Option<String>) -> Self {
        // PeerIds are used only for informational purposes, but just in case, make a
        // big number so it stands out

        Self::new_admin(PeerId::from(1024), url, api_secret, &Connector::default())
    }

    pub fn from_single_endpoint(
        peer: PeerId,
        url: SafeUrl,
        api_secret: &Option<String>,
        connector: &Connector,
        admin_id: Option<PeerId>,
    ) -> Self {
        Self::from_endpoints(once((peer, url)), api_secret, connector, admin_id)
    }

    pub fn from_endpoints(
        peers: impl IntoIterator<Item = (PeerId, SafeUrl)>,
        api_secret: &Option<String>,
        connector: &Connector,
        admin_id: Option<PeerId>,
    ) -> Self {
        let connector = match connector {
            Connector::Tcp => {
                WebsocketConnector::new(peers.into_iter().collect(), api_secret.clone()).into_dyn()
            }
            #[cfg(all(feature = "tor", not(target_family = "wasm")))]
            Connector::Tor => {
                TorConnector::new(peers.into_iter().collect(), api_secret.clone()).into_dyn()
            }
            #[cfg(all(feature = "tor", target_family = "wasm"))]
            Connector::Tor => unimplemented!(),
        };

        GlobalFederationApiWithCache::new(ReconnectFederationApi::new(&connector, admin_id)).into()
    }

    pub fn from_invite_code(connector: &Connector, invite_code: &InviteCode) -> Self {
        Self::from_endpoints(
            invite_code.peers(),
            &invite_code.api_secret(),
            connector,
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

    /// Fetches the server consensus hash if enough peers agree on it
    async fn server_config_consensus_hash(&self) -> FederationResult<sha256::Hash>;

    async fn upload_backup(&self, request: &SignedBackupRequest) -> FederationResult<()>;

    async fn download_backup(
        &self,
        id: &secp256k1::PublicKey,
    ) -> FederationResult<BTreeMap<PeerId, Option<ClientBackupSnapshot>>>;

    /// Sets the password used to decrypt the configs and authenticate
    ///
    /// Must be called first before any other calls to the API
    async fn set_password(&self, auth: ApiAuth) -> FederationResult<()>;

    /// During config gen, sets the server connection containing our endpoints
    ///
    /// Optionally sends our server info to the config gen leader using
    /// `add_config_gen_peer`
    async fn set_config_gen_connections(
        &self,
        info: ConfigGenConnectionsRequest,
        auth: ApiAuth,
    ) -> FederationResult<()>;

    /// During config gen, used for an API-to-API call that adds a peer's server
    /// connection info to the leader.
    ///
    /// Note this call will fail until the leader has their API running and has
    /// `set_server_connections` so clients should retry.
    ///
    /// This call is not authenticated because it's guardian-to-guardian
    async fn add_config_gen_peer(&self, peer: PeerServerParams) -> FederationResult<()>;

    /// During config gen, gets all the server connections we've received from
    /// peers using `add_config_gen_peer`
    ///
    /// Could be called on the leader, so it's not authenticated
    async fn get_config_gen_peers(&self) -> FederationResult<Vec<PeerServerParams>>;

    /// Gets the default config gen params which can be configured by the
    /// leader, gives them a template to modify
    async fn get_default_config_gen_params(
        &self,
        auth: ApiAuth,
    ) -> FederationResult<ConfigGenParamsRequest>;

    /// Leader sets the consensus params, everyone sets the local params
    ///
    /// After calling this `ConfigGenParams` can be created for DKG
    async fn set_config_gen_params(
        &self,
        requested: ConfigGenParamsRequest,
        auth: ApiAuth,
    ) -> FederationResult<()>;

    /// Returns the consensus config gen params, followers will delegate this
    /// call to the leader.  Once this endpoint returns successfully we can run
    /// DKG.
    async fn consensus_config_gen_params(&self) -> FederationResult<ConfigGenParamsResponse>;

    /// Runs DKG, can only be called once after configs have been generated in
    /// `get_consensus_config_gen_params`.  If DKG fails this returns a 500
    /// error and config gen must be restarted.
    async fn run_dkg(&self, auth: ApiAuth) -> FederationResult<()>;

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
}

impl WebsocketConnector {
    pub fn new(peers: BTreeMap<PeerId, SafeUrl>, api_secret: Option<String>) -> Self {
        Self { peers, api_secret }
    }
}

#[async_trait]
impl IClientConnector for WebsocketConnector {
    fn peers(&self) -> BTreeSet<PeerId> {
        self.peers.keys().copied().collect()
    }

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynClientConnection> {
        let api_endpoint = self
            .peers
            .get(&peer)
            .expect("Could not find websocket api endpoint for peer {peer}");

        #[cfg(not(target_family = "wasm"))]
        let mut client = {
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
                url.set_username("fedimint").map_err(|_| {
                    JsonRpcClientError::Transport(anyhow::format_err!("invalid username").into())
                })?;
                url.set_password(Some(&api_secret)).map_err(|_| {
                    JsonRpcClientError::Transport(anyhow::format_err!("invalid secret").into())
                })?;

                let client = client.build(url.as_str()).await?;

                return Ok(client.into_dyn());
            }
        }

        let client = client.build(api_endpoint.as_str()).await?;

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
    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynClientConnection> {
        let api_endpoint = self
            .peers
            .get(&peer)
            .expect("Could not find websocket api endpoint for peer {peer}");

        let tor_config = TorClientConfig::default();
        let tor_client = TorClient::create_bootstrapped(tor_config)
            .await
            .map_err(|e| JsonRpcClientError::Transport(e.into()))?
            .isolated_client();

        debug!("Successfully created and bootstrapped the `TorClient`, for given `TorConfig`.");

        // TODO: (@leonardo) should we implement our `IntoTorAddr` for `SafeUrl`
        // instead?
        let addr = (
            api_endpoint
                .host_str()
                .expect("It should've asserted for `host` on construction"),
            api_endpoint
                .port_or_known_default()
                .expect("It should've asserted for `port`, or used a default one, on construction"),
        );
        let tor_addr = TorAddr::from(addr).map_err(|e| JsonRpcClientError::Transport(e.into()))?;
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
                .map_err(|e| JsonRpcClientError::Transport(e.into()))?;

            debug!(
                ?tor_addr_clone,
                "Successfully connected to onion address `TorAddr`, and established an anonymized `DataStream`"
            );
            anonymized_stream
        } else {
            let anonymized_stream = tor_client
                .connect(tor_addr)
                .await
                .map_err(|e| JsonRpcClientError::Transport(e.into()))?;

            debug!(?tor_addr_clone, "Successfully connected to `Hostname`or `Ip` `TorAddr`, and established an anonymized `DataStream`");
            anonymized_stream
        };

        let is_tls = match api_endpoint.scheme() {
            "wss" => true,
            "ws" => false,
            unexpected_scheme => {
                let error =
                    format!("`{unexpected_scheme}` not supported, it's expected `ws` or `wss`!");
                return Err(anyhow!(error));
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
                    .await?;

                Ok(client.into_dyn())
            }
            Some(tls_connector) => {
                let host = api_endpoint
                    .host_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| {
                        JsonRpcClientError::Transport(anyhow!("Invalid host!").into())
                    })?;

                // FIXME: (@leonardo) Is this leaking any data ? Should investigate it further
                // if it's really needed.
                let server_name = rustls_pki_types::ServerName::try_from(host)
                    .map_err(|e| JsonRpcClientError::Transport(e.into()))?;

                let anonymized_tls_stream = tls_connector
                    .connect(server_name, anonymized_stream)
                    .await
                    .map_err(|e| JsonRpcClientError::Transport(e.into()))?;

                let client = ws_client_builder
                    .build_with_stream(api_endpoint.as_str(), anonymized_tls_stream)
                    .await?;

                Ok(client.into_dyn())
            }
        }
    }
}

#[async_trait]
impl IClientConnection for WsClient {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> anyhow::Result<Value> {
        let method = match method {
            ApiMethod::Core(method) => method,
            ApiMethod::Module(module_id, method) => format!("module_{module_id}_{method}"),
        };

        Ok(ClientT::request(self, &method, [request.to_json()]).await?)
    }

    async fn await_disconnection(&self) {
        self.on_disconnect().await;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiMethod {
    Core(String),
    Module(ModuleInstanceId, String),
}

pub type DynClientConnector = Arc<dyn IClientConnector>;

/// Allows to connect to peers. Connections are request based and should be
/// authenticated and encrypted for production deployments.
#[async_trait]
pub trait IClientConnector: Send + Sync + 'static {
    fn peers(&self) -> BTreeSet<PeerId>;

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynClientConnection>;

    fn into_dyn(self) -> DynClientConnector
    where
        Self: Sized,
    {
        Arc::new(self)
    }
}

pub type DynClientConnection = Arc<dyn IClientConnection>;

#[async_trait]
pub trait IClientConnection: Debug + Send + Sync + 'static {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> anyhow::Result<Value>;

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
    peers: BTreeSet<PeerId>,
    admin_id: Option<PeerId>,
    module_id: Option<ModuleInstanceId>,
    connections: ReconnectClientConnections,
}

impl ReconnectFederationApi {
    fn new(connector: &DynClientConnector, admin_id: Option<PeerId>) -> Self {
        Self {
            peers: connector.peers(),
            admin_id,
            module_id: None,
            connections: ReconnectClientConnections::new(connector),
        }
    }

    pub fn new_admin(
        peer: PeerId,
        url: SafeUrl,
        api_secret: &Option<String>,
        connector: &Connector,
    ) -> Self {
        Self::from_endpoints(once((peer, url)), api_secret, connector, Some(peer))
    }

    pub fn from_endpoints(
        peers: impl IntoIterator<Item = (PeerId, SafeUrl)>,
        api_secret: &Option<String>,
        connector: &Connector,
        admin_id: Option<PeerId>,
    ) -> Self {
        let connector = match connector {
            Connector::Tcp => {
                WebsocketConnector::new(peers.into_iter().collect(), api_secret.clone()).into_dyn()
            }
            #[cfg(all(feature = "tor", not(target_family = "wasm")))]
            Connector::Tor => {
                TorConnector::new(peers.into_iter().collect(), api_secret.clone()).into_dyn()
            }
            #[cfg(all(feature = "tor", target_family = "wasm"))]
            Connector::Tor => unimplemented!(),
        };

        ReconnectFederationApi::new(&connector, admin_id)
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
            peers: self.peers.clone(),
            admin_id: self.admin_id,
            module_id: Some(id),
            connections: self.connections.clone(),
        }
        .into()
    }

    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> JsonRpcResult<Value> {
        let method = match self.module_id {
            Some(module_id) => ApiMethod::Module(module_id, method.to_string()),
            None => ApiMethod::Core(method.to_string()),
        };

        self.connections
            .request(peer_id, method, params.clone())
            .await
            .map_err(|e| JsonRpcClientError::Transport(e.into()))
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
    ) -> anyhow::Result<Value> {
        self.connections
            .get(&peer)
            .expect("Could not find client connection for peer {peer}")
            .connection()
            .await
            .context("Failed to connect to peer")?
            .request(method, request)
            .await
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
                    let n_request = receiver.len();

                    match connector.connect(peer).await {
                        Ok(connection) => {
                            info!(target: LOG_CLIENT_NET_API, "Connected to peer api");

                            sender.send(connection.clone()).ok();

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

                            info!(target: LOG_CLIENT_NET_API, "Disconnected from peer api");

                            backoff = api_networking_backoff();
                        }
                        Err(e) => {
                            info!(target: LOG_CLIENT_NET_API, "Failed to connect to peer api {e}");

                            // We need to drain the channel for the pending requests to fail.

                            for _ in 0..n_request {
                                receiver.try_recv().expect("Items exist");
                            }

                            fedimint_core::task::sleep(
                                backoff.next().expect("No limit to the number of retries"),
                            )
                            .await;
                        }
                    }
                }

                info!(target: LOG_CLIENT_NET_API, "Shutting down peer api connection task");
            }
            .instrument(info_span!("peer-api-connection", ?peer)),
        );

        ClientConnection { sender }
    }

    async fn connection(&self) -> Option<DynClientConnection> {
        let (sender, receiver) = oneshot::channel();

        self.sender.send(sender).await.ok()?;

        receiver.await.ok()
    }
}

#[cfg(all(feature = "enable_iroh", not(target_family = "wasm")))]
mod iroh {
    use std::collections::{BTreeMap, BTreeSet};

    use anyhow::anyhow;
    use async_trait::async_trait;
    use bitcoin::key::rand::rngs::OsRng;
    use fedimint_core::module::{ApiError, ApiRequestErased};
    use fedimint_core::PeerId;
    use iroh::endpoint::Connection;
    use iroh::{Endpoint, NodeId, SecretKey};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    use super::{ApiMethod, DynClientConnection, IClientConnection, IClientConnector};

    const FEDIMINT_ALPN: &[u8] = "FEDIMINT_ALPN".as_bytes();

    #[derive(Debug, Clone)]
    pub struct IrohConnector {
        node_ids: BTreeMap<PeerId, NodeId>,
        endpoint: Endpoint,
    }

    impl IrohConnector {
        #[allow(unused)]
        pub async fn new(peers: BTreeMap<PeerId, NodeId>) -> anyhow::Result<Self> {
            Ok(Self {
                node_ids: peers,
                endpoint: Endpoint::builder()
                    .discovery_n0()
                    .secret_key(SecretKey::generate(&mut OsRng))
                    .alpns(vec![FEDIMINT_ALPN.to_vec()])
                    .bind()
                    .await?,
            })
        }
    }

    #[async_trait]
    impl IClientConnector for IrohConnector {
        fn peers(&self) -> BTreeSet<PeerId> {
            self.node_ids.keys().copied().collect()
        }

        async fn connect(&self, peer: PeerId) -> anyhow::Result<DynClientConnection> {
            let node_id = *self
                .node_ids
                .get(&peer)
                .expect("Could not find node id for peer {peer}");

            let connection = self.endpoint.connect(node_id, FEDIMINT_ALPN).await?;

            Ok(connection.into_dyn())
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct IrohRequest {
        method: ApiMethod,
        request: ApiRequestErased,
    }

    #[async_trait]
    impl IClientConnection for Connection {
        async fn request(
            &self,
            method: ApiMethod,
            request: ApiRequestErased,
        ) -> anyhow::Result<Value> {
            let json = serde_json::to_vec(&IrohRequest { method, request })?;

            let (mut sink, mut stream) = self.open_bi().await?;

            sink.write_all(&json).await?;

            sink.finish()?;

            let response = stream.read_to_end(1_000_000).await?;

            let response = serde_json::from_slice::<Result<Value, ApiError>>(&response)?;

            response.map_err(|e| anyhow!("Api Error: {:?}", e))
        }

        async fn await_disconnection(&self) {
            self.closed().await;
        }
    }
}

/// The status of a server, including how it views its peers
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FederationStatus {
    pub session_count: u64,
    pub status_by_peer: HashMap<PeerId, PeerStatus>,
    pub peers_online: u64,
    pub peers_offline: u64,
    /// This should always be 0 if everything is okay, so a monitoring tool
    /// should generate an alert if this is not the case.
    pub peers_flagged: u64,
    pub scheduled_shutdown: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStatus {
    pub last_contribution: Option<u64>,
    pub connection_status: P2PConnectionStatus,
    /// Indicates that this peer needs attention from the operator since
    /// it has not contributed to the consensus in a long time
    pub flagged: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum P2PConnectionStatus {
    #[default]
    Disconnected,
    Connected,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StatusResponse {
    pub server: ServerStatus,
    pub federation: Option<FederationStatus>,
}

/// Archive of all the guardian config files that can be used to recover a lost
/// guardian node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardianConfigBackup {
    #[serde(with = "fedimint_core::hex::serde")]
    pub tar_archive_bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use fedimint_core::config::FederationId;

    use super::*;

    #[test]
    fn converts_invite_code() {
        let connect = InviteCode::new(
            "ws://test1".parse().unwrap(),
            PeerId::from(1),
            FederationId::dummy(),
            Some("api_secret".into()),
        );

        let bech32 = connect.to_string();
        let connect_parsed = InviteCode::from_str(&bech32).expect("parses");
        assert_eq!(connect, connect_parsed);

        let json = serde_json::to_string(&connect).unwrap();
        let connect_as_string: String = serde_json::from_str(&json).unwrap();
        assert_eq!(connect_as_string, bech32);
        let connect_parsed_json: InviteCode = serde_json::from_str(&json).unwrap();
        assert_eq!(connect_parsed_json, connect_parsed);
    }

    #[test]
    fn creates_essential_guardians_invite_code() {
        let mut peer_to_url_map = BTreeMap::new();
        peer_to_url_map.insert(PeerId::from(0), "ws://test1".parse().expect("URL fail"));
        peer_to_url_map.insert(PeerId::from(1), "ws://test2".parse().expect("URL fail"));
        peer_to_url_map.insert(PeerId::from(2), "ws://test3".parse().expect("URL fail"));
        peer_to_url_map.insert(PeerId::from(3), "ws://test4".parse().expect("URL fail"));
        let max_size = peer_to_url_map.to_num_peers().max_evil() + 1;

        let code =
            InviteCode::new_with_essential_num_guardians(&peer_to_url_map, FederationId::dummy());

        assert_eq!(FederationId::dummy(), code.federation_id());

        let expected_map: BTreeMap<PeerId, SafeUrl> =
            peer_to_url_map.into_iter().take(max_size).collect();
        assert_eq!(expected_map, code.peers());
    }
}
