use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{self, Debug, Display};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, result};

use anyhow::anyhow;
use base64::Engine as _;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1;
use fedimint_core::admin_client::{
    ConfigGenConnectionsRequest, ConfigGenParamsRequest, ConfigGenParamsResponse, PeerServerParams,
    ServerStatus,
};
use fedimint_core::backup::ClientBackupSnapshot;
use fedimint_core::config::ClientConfig;
use fedimint_core::core::backup::SignedBackupRequest;
use fedimint_core::core::{Decoder, DynOutputOutcome, ModuleInstanceId, OutputOutcome};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::endpoint_constants::{
    ADD_CONFIG_GEN_PEER_ENDPOINT, AUDIT_ENDPOINT, AUTH_ENDPOINT, AWAIT_OUTPUT_OUTCOME_ENDPOINT,
    AWAIT_SESSION_OUTCOME_ENDPOINT, AWAIT_TRANSACTION_ENDPOINT, BACKUP_ENDPOINT,
    CONFIG_GEN_PEERS_ENDPOINT, CONSENSUS_CONFIG_GEN_PARAMS_ENDPOINT,
    DEFAULT_CONFIG_GEN_PARAMS_ENDPOINT, GUARDIAN_CONFIG_BACKUP_ENDPOINT, RECOVER_ENDPOINT,
    RESTART_FEDERATION_SETUP_ENDPOINT, RUN_DKG_ENDPOINT, SERVER_CONFIG_CONSENSUS_HASH_ENDPOINT,
    SESSION_COUNT_ENDPOINT, SESSION_STATUS_ENDPOINT, SET_CONFIG_GEN_CONNECTIONS_ENDPOINT,
    SET_CONFIG_GEN_PARAMS_ENDPOINT, SET_PASSWORD_ENDPOINT, START_CONSENSUS_ENDPOINT,
    STATUS_ENDPOINT, SUBMIT_TRANSACTION_ENDPOINT, VERIFIED_CONFIGS_ENDPOINT,
    VERIFY_CONFIG_HASH_ENDPOINT,
};
use fedimint_core::fmt_utils::{AbbreviateDebug, AbbreviateJson};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::audit::AuditSummary;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiAuth, ApiRequestErased, ApiVersion, SerdeModuleEncoding};
use fedimint_core::session_outcome::{AcceptedItem, SessionOutcome, SessionStatus};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::transaction::{SerdeTransaction, Transaction, TransactionSubmissionOutcome};
use fedimint_core::util::SafeUrl;
use fedimint_core::{
    apply, async_trait_maybe_send, dyn_newtype_define, runtime, NumPeersExt, OutPoint, PeerId,
    TransactionId,
};
use fedimint_logging::LOG_CLIENT_NET_API;
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use itertools::Itertools;
use jsonrpsee_core::client::{ClientT, Error as JsonRpcClientError};
use jsonrpsee_core::DeserializeOwned;
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{HeaderMap, HeaderValue};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::OnceCell;
use tracing::{debug, error, instrument, trace, warn};

use crate::query::{FilterMapThreshold, QueryStep, QueryStrategy, ThresholdConsensus};

mod federation_peer_client;

use federation_peer_client::FederationPeer;

pub type PeerResult<T> = Result<T, PeerError>;
pub type JsonRpcResult<T> = Result<T, JsonRpcClientError>;
pub type FederationResult<T> = Result<T, FederationError>;
pub type SerdeOutputOutcome = SerdeModuleEncoding<DynOutputOutcome>;

/// An API request error when calling a single federation peer
#[derive(Debug, Error)]
pub enum PeerError {
    #[error("Response deserialization error: {0}")]
    ResponseDeserialization(anyhow::Error),
    #[error("Invalid peer id: {peer_id}")]
    InvalidPeerId { peer_id: PeerId },
    #[error("Rpc error: {0}")]
    Rpc(#[from] JsonRpcClientError),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

impl PeerError {
    /// Report errors that are worth reporting
    ///
    /// The goal here is to avoid spamming logs with errors that happen commonly
    /// for all sorts of expected reasons, while printing ones that suggest
    /// there's a problem.
    pub fn report_if_important(&self, peer_id: PeerId) {
        let important = match self {
            PeerError::ResponseDeserialization(_)
            | PeerError::InvalidPeerId { .. }
            | PeerError::InvalidResponse(_) => true,
            PeerError::Rpc(rpc_e) => match rpc_e {
                // TODO: Does this cover all retryable cases?
                JsonRpcClientError::Transport(_) | JsonRpcClientError::RequestTimeout => false,
                JsonRpcClientError::RestartNeeded(_)
                | JsonRpcClientError::Call(_)
                | JsonRpcClientError::ParseError(_)
                | JsonRpcClientError::InvalidSubscriptionId
                | JsonRpcClientError::InvalidRequestId(_)
                | JsonRpcClientError::Custom(_)
                | JsonRpcClientError::HttpNotImplemented
                | JsonRpcClientError::EmptyBatchRequest(_)
                | JsonRpcClientError::RegisterMethod(_) => true,
            },
        };

        trace!(target: LOG_CLIENT_NET_API, error = %self, "PeerError");

        if important {
            warn!(target: LOG_CLIENT_NET_API, error = %self, %peer_id, "Unusual PeerError");
        }
    }
}

/// An API request error when calling an entire federation
///
/// Generally all Federation errors are retriable.
#[derive(Debug, Error)]
pub struct FederationError {
    method: String,
    params: serde_json::Value,
    general: Option<anyhow::Error>,
    peers: BTreeMap<PeerId, PeerError>,
}

impl Display for FederationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Federation rpc error {")?;
        if let Some(general) = self.general.as_ref() {
            f.write_fmt(format_args!("method => {}), ", self.method))?;
            f.write_fmt(format_args!(
                "params => {:?}), ",
                AbbreviateJson(&self.params)
            ))?;
            f.write_fmt(format_args!("general => {general})"))?;
            if !self.peers.is_empty() {
                f.write_str(", ")?;
            }
        }
        for (i, (peer, e)) in self.peers.iter().enumerate() {
            f.write_fmt(format_args!("{peer} => {e})"))?;
            if i == self.peers.len() - 1 {
                f.write_str(", ")?;
            }
        }
        f.write_str("}")?;
        Ok(())
    }
}

impl FederationError {
    pub fn general(
        method: impl Into<String>,
        params: impl Serialize,
        e: impl Into<anyhow::Error>,
    ) -> FederationError {
        FederationError {
            method: method.into(),
            params: serde_json::to_value(params).unwrap_or_default(),
            general: Some(e.into()),
            peers: BTreeMap::default(),
        }
    }

    pub fn new_one_peer(
        peer_id: PeerId,
        method: impl Into<String>,
        params: impl Serialize,
        error: PeerError,
    ) -> Self {
        Self {
            method: method.into(),
            params: serde_json::to_value(params).expect("Serialization of valid params won't fail"),
            general: None,
            peers: [(peer_id, error)].into_iter().collect(),
        }
    }

    /// Report any errors
    pub fn report_if_important(&self) {
        if let Some(error) = self.general.as_ref() {
            warn!(target: LOG_CLIENT_NET_API, %error, "General FederationError");
        }
        for (peer_id, e) in &self.peers {
            e.report_if_important(*peer_id);
        }
    }

    /// Get the general error if any.
    pub fn get_general_error(&self) -> Option<&anyhow::Error> {
        self.general.as_ref()
    }

    /// Get errors from different peers.
    pub fn get_peer_errors(&self) -> impl Iterator<Item = (PeerId, &PeerError)> {
        self.peers.iter().map(|(peer, error)| (*peer, error))
    }
}

type OutputOutcomeResult<O> = result::Result<O, OutputOutcomeError>;

#[derive(Debug, Error)]
pub enum OutputOutcomeError {
    #[error("Response deserialization error: {0}")]
    ResponseDeserialization(anyhow::Error),
    #[error("Federation error: {0}")]
    Federation(#[from] FederationError),
    #[error("Core error: {0}")]
    Core(#[from] anyhow::Error),
    #[error("Transaction rejected: {0}")]
    Rejected(String),
    #[error("Invalid output index {out_idx}, larger than {outputs_num} in the transaction")]
    InvalidVout { out_idx: u64, outputs_num: usize },
    #[error("Timeout reached after waiting {}s", .0.as_secs())]
    Timeout(Duration),
}

impl OutputOutcomeError {
    pub fn report_if_important(&self) {
        let important = match self {
            OutputOutcomeError::Federation(e) => {
                e.report_if_important();
                return;
            }
            OutputOutcomeError::Core(_)
            | OutputOutcomeError::InvalidVout { .. }
            | OutputOutcomeError::ResponseDeserialization(_) => true,
            OutputOutcomeError::Rejected(_) | OutputOutcomeError::Timeout(_) => false,
        };

        trace!(target: LOG_CLIENT_NET_API, error = %self, "OutputOutcomeError");

        if important {
            warn!(target: LOG_CLIENT_NET_API, error = %self, "Uncommon OutputOutcomeError");
        }
    }

    /// Was the transaction rejected (which is final)
    pub fn is_rejected(&self) -> bool {
        matches!(
            self,
            OutputOutcomeError::Rejected(_) | OutputOutcomeError::InvalidVout { .. }
        )
    }
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
        params: &[Value],
    ) -> result::Result<Value, JsonRpcClientError>;
}

/// Set of api versions for each component (core + modules)
///
/// E.g. result of federated common api versions discovery.
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct ApiVersionSet {
    pub core: ApiVersion,
    pub modules: BTreeMap<ModuleInstanceId, ApiVersion>,
}

/// An extension trait allowing to making federation-wide API call on top
/// [`IRawFederationApi`].
#[apply(async_trait_maybe_send!)]
pub trait FederationApiExt: IRawFederationApi {
    /// Make a request to a single peer in the federation with an optional
    /// timeout.
    async fn request_single_peer(
        &self,
        timeout: Option<Duration>,
        method: String,
        params: ApiRequestErased,
        peer_id: PeerId,
    ) -> JsonRpcResult<jsonrpsee_core::JsonValue> {
        let request = async {
            self.request_raw(peer_id, &method, &[params.to_json()])
                .await
        };

        if let Some(timeout) = timeout {
            match fedimint_core::runtime::timeout(timeout, request).await {
                Ok(result) => result,
                Err(_timeout) => Err(JsonRpcClientError::RequestTimeout),
            }
        } else {
            request.await
        }
    }
    async fn request_single_peer_typed<Ret>(
        &self,
        timeout: Option<Duration>,
        method: String,
        params: ApiRequestErased,
        peer_id: PeerId,
    ) -> PeerResult<Ret>
    where
        Ret: DeserializeOwned,
    {
        self.request_single_peer(timeout, method, params, peer_id)
            .await
            .map_err(PeerError::Rpc)
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| PeerError::ResponseDeserialization(e.into()))
            })
    }

    /// Like [`Self::request_single_peer`], but API more like
    /// [`Self::request_with_strategy`].
    async fn request_single_peer_federation<FedRet>(
        &self,
        timeout: Option<Duration>,
        method: String,
        params: ApiRequestErased,
        peer_id: PeerId,
    ) -> FederationResult<FedRet>
    where
        FedRet: serde::de::DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        Ok(self
            .request_single_peer(timeout, method.clone(), params.clone(), peer_id)
            .await
            .map_err(PeerError::Rpc)
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| PeerError::ResponseDeserialization(e.into()))
            })
            .map_err(|e| FederationError::new_one_peer(peer_id, method, params, e))?)
    }

    /// Make an aggregate request to federation, using `strategy` to logically
    /// merge the responses.
    async fn request_with_strategy<PeerRet: serde::de::DeserializeOwned, FedRet: Debug>(
        &self,
        mut strategy: impl QueryStrategy<PeerRet, FedRet> + MaybeSend,
        method: String,
        params: ApiRequestErased,
    ) -> FederationResult<FedRet> {
        #[cfg(not(target_family = "wasm"))]
        let mut futures = FuturesUnordered::<Pin<Box<dyn Future<Output = _> + Send>>>::new();
        #[cfg(target_family = "wasm")]
        let mut futures = FuturesUnordered::<Pin<Box<dyn Future<Output = _>>>>::new();

        let peers = self.all_peers();

        for peer_id in peers {
            futures.push(Box::pin(async {
                let request = async {
                    self.request_raw(*peer_id, &method, &[params.to_json()])
                        .await
                        .map(AbbreviateDebug)
                };

                PeerResponse {
                    peer: *peer_id,
                    result: request.await,
                }
            }));
        }

        let mut peer_delay_ms = BTreeMap::new();

        // Delegates the response handling to the `QueryStrategy` with an exponential
        // back-off with every new set of requests
        let max_delay_ms = 1000;
        loop {
            let response = futures.next().await;
            trace!(target: LOG_CLIENT_NET_API, ?response, method, params = ?AbbreviateDebug(params.to_json()), "Received peer response");
            match response {
                Some(PeerResponse { peer, result }) => {
                    let result: PeerResult<PeerRet> =
                        result.map_err(PeerError::Rpc).and_then(|o| {
                            serde_json::from_value::<PeerRet>(o.0)
                                .map_err(|e| PeerError::ResponseDeserialization(e.into()))
                        });

                    let strategy_step = strategy.process(peer, result);
                    trace!(
                        target: LOG_CLIENT_NET_API,
                        method,
                        ?params,
                        ?strategy_step,
                        "Taking strategy step to the response after peer response"
                    );
                    match strategy_step {
                        QueryStep::Retry(peers) => {
                            for retry_peer in peers {
                                let mut delay_ms =
                                    peer_delay_ms.get(&retry_peer).copied().unwrap_or(10);
                                delay_ms = cmp::min(max_delay_ms, delay_ms * 2);
                                peer_delay_ms.insert(retry_peer, delay_ms);

                                futures.push(Box::pin({
                                    let method = &method;
                                    let params = &params;
                                    async move {
                                        // Note: we need to sleep inside the retrying future,
                                        // so that `futures` is being polled continuously
                                        runtime::sleep(Duration::from_millis(delay_ms)).await;
                                        PeerResponse {
                                            peer: retry_peer,
                                            result: self
                                                .request_raw(
                                                    retry_peer,
                                                    method,
                                                    &[params.to_json()],
                                                )
                                                .await
                                                .map(AbbreviateDebug),
                                        }
                                    }
                                }));
                            }
                        }
                        QueryStep::Continue => {}
                        QueryStep::Failure { general, peers } => {
                            return Err(FederationError {
                                method: method.clone(),
                                params: params.params.clone(),
                                general,
                                peers,
                            })
                        }
                        QueryStep::Success(response) => return Ok(response),
                    }
                }
                None => {
                    panic!("Query strategy ran out of peers to query without returning a result");
                }
            }
        }
    }

    async fn request_current_consensus<Ret>(
        &self,
        method: String,
        params: ApiRequestErased,
    ) -> FederationResult<Ret>
    where
        Ret: serde::de::DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        self.request_with_strategy(
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
        Ret: serde::de::DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        let Some(self_peer_id) = self.self_peer() else {
            return Err(FederationError::general(
                method,
                params,
                anyhow::format_err!("Admin peer_id not set"),
            ));
        };
        self.request_single_peer_federation(
            None,
            method.into(),
            params.with_auth(auth),
            self_peer_id,
        )
        .await
    }

    async fn request_admin_no_auth<Ret>(
        &self,
        method: &str,
        params: ApiRequestErased,
    ) -> FederationResult<Ret>
    where
        Ret: serde::de::DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        let Some(self_peer_id) = self.self_peer() else {
            return Err(FederationError::general(
                method,
                params,
                anyhow::format_err!("Admin peer_id not set"),
            ));
        };

        self.request_single_peer_federation(None, method.into(), params, self_peer_id)
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
    pub fn from_pre_peer_id_admin_endpoint(url: SafeUrl, api_secret: &Option<String>) -> Self {
        // PeerIds are used only for informational purposes, but just in case, make a
        // big number so it stands out
        let peer_id = PeerId::from(1024);
        GlobalFederationApiWithCache::new(
            WsFederationApi::new(vec![(peer_id, url)], api_secret).with_self_peer_id(peer_id),
        )
        .into()
    }

    pub fn from_single_endpoint(peer: PeerId, url: SafeUrl, api_secret: &Option<String>) -> Self {
        GlobalFederationApiWithCache::new(WsFederationApi::new(vec![(peer, url)], api_secret))
            .into()
    }

    pub fn from_endpoints(peers: Vec<(PeerId, SafeUrl)>, api_secret: &Option<String>) -> Self {
        GlobalFederationApiWithCache::new(WsFederationApi::new(peers, api_secret)).into()
    }

    pub fn from_config(config: &ClientConfig, api_secret: &Option<String>) -> Self {
        GlobalFederationApiWithCache::new(WsFederationApi::from_config(config, api_secret)).into()
    }

    pub fn from_config_admin(
        config: &ClientConfig,
        api_secret: &Option<String>,
        self_peer_id: PeerId,
    ) -> Self {
        GlobalFederationApiWithCache::new(
            WsFederationApi::from_config(config, api_secret).with_self_peer_id(self_peer_id),
        )
        .into()
    }

    pub fn from_invite_code(invite_code: &InviteCode) -> Self {
        GlobalFederationApiWithCache::new(WsFederationApi::new(
            invite_code.peers().into_iter().collect_vec(),
            &invite_code.api_secret(),
        ))
        .into()
    }

    pub async fn await_output_outcome<R>(
        &self,
        outpoint: OutPoint,
        timeout: Duration,
        module_decoder: &Decoder,
    ) -> OutputOutcomeResult<R>
    where
        R: OutputOutcome,
    {
        fedimint_core::runtime::timeout(timeout, async {
            let outcome: SerdeOutputOutcome = self
                .inner
                .request_current_consensus(
                    AWAIT_OUTPUT_OUTCOME_ENDPOINT.to_owned(),
                    ApiRequestErased::new(outpoint),
                )
                .await
                .map_err(OutputOutcomeError::Federation)?;

            deserialize_outcome(&outcome, module_decoder)
        })
        .await
        .map_err(|_| OutputOutcomeError::Timeout(timeout))?
    }
}

/// The API for the global (non-module) endpoints
#[apply(async_trait_maybe_send!)]
pub trait IGlobalFederationApi: IRawFederationApi {
    async fn submit_transaction(
        &self,
        tx: Transaction,
    ) -> FederationResult<SerdeModuleEncoding<TransactionSubmissionOutcome>>;

    async fn await_block(
        &self,
        block_index: u64,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionOutcome>;

    async fn get_session_status(
        &self,
        block_index: u64,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionStatus>;

    async fn session_count(&self) -> FederationResult<u64>;

    async fn await_transaction(&self, txid: TransactionId) -> FederationResult<TransactionId>;

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

/// [`IGlobalFederationApi`] wrapping some `T: IRawFederationApi` and adding
/// a tiny bit of caching.
#[derive(Debug)]
struct GlobalFederationApiWithCache<T> {
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
                NonZeroUsize::new(32).expect("is non-zero"),
            ))),
            get_session_status_lru: Arc::new(tokio::sync::Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(32).expect("is non-zero"),
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
        debug!(block_index, "Awaiting block's outcome from Federation");
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
        debug!(block_index, "Fetching block's outcome from Federation");
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
}

/// Mint API client that will try to run queries against all `peers` expecting
/// equal results from at least `min_eq_results` of them. Peers that return
/// differing results are returned as a peer faults list.
#[derive(Debug, Clone)]
pub struct WsFederationApi<C = WsClient> {
    peer_ids: BTreeSet<PeerId>,
    self_peer_id: Option<PeerId>,
    peers: Arc<Vec<FederationPeer<C>>>,
    module_id: Option<ModuleInstanceId>,
}

impl<C: JsonRpcClient + Debug + 'static> IModuleFederationApi for WsFederationApi<C> {}

/// Implementation of API calls over websockets
///
/// Can function as either the global or module API
#[apply(async_trait_maybe_send!)]
impl<C: JsonRpcClient + Debug + 'static> IRawFederationApi for WsFederationApi<C> {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.peer_ids
    }

    fn self_peer(&self) -> Option<PeerId> {
        self.self_peer_id
    }

    fn with_module(&self, id: ModuleInstanceId) -> DynModuleApi {
        WsFederationApi {
            peer_ids: self.peer_ids.clone(),
            peers: self.peers.clone(),
            module_id: Some(id),
            self_peer_id: self.self_peer_id,
        }
        .into()
    }

    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &[Value],
    ) -> JsonRpcResult<Value> {
        let peer = self
            .peers
            .iter()
            .find(|m| m.peer_id == peer_id)
            .ok_or_else(|| JsonRpcClientError::Custom(format!("Invalid peer_id: {peer_id}")))?;

        let method = match self.module_id {
            None => method.to_string(),
            Some(id) => format!("module_{id}_{method}"),
        };
        peer.request(&method, params).await
    }
}

#[apply(async_trait_maybe_send!)]
pub trait JsonRpcClient: ClientT + Sized + MaybeSend + MaybeSync {
    async fn connect(
        url: &SafeUrl,
        api_secret: Option<String>,
    ) -> result::Result<Self, JsonRpcClientError>;
    fn is_connected(&self) -> bool;
}

#[apply(async_trait_maybe_send!)]
impl JsonRpcClient for WsClient {
    async fn connect(
        url: &SafeUrl,
        api_secret: Option<String>,
    ) -> result::Result<Self, JsonRpcClientError> {
        #[cfg(not(target_family = "wasm"))]
        let mut client = WsClientBuilder::default().max_concurrent_requests(u16::MAX as usize);

        #[cfg(target_family = "wasm")]
        let client = WsClientBuilder::default().max_concurrent_requests(u16::MAX as usize);

        if let Some(api_secret) = api_secret {
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
                let mut url = url.clone();
                url.set_username("fedimint").map_err(|_| {
                    JsonRpcClientError::Transport(anyhow::format_err!("invalid username"))
                })?;
                url.set_password(Some(&api_secret)).map_err(|_| {
                    JsonRpcClientError::Transport(anyhow::format_err!("invalid secret"))
                })?;
                return client.build(url.as_str()).await;
            }
        }
        client.build(url.as_str()).await
    }

    fn is_connected(&self) -> bool {
        self.is_connected()
    }
}

impl WsFederationApi<WsClient> {
    /// Creates a new API client
    pub fn new(peers: Vec<(PeerId, SafeUrl)>, api_secret: &Option<String>) -> Self {
        Self::new_with_client(peers, None, api_secret)
    }

    /// Creates a new API client from a client config
    pub fn from_config(config: &ClientConfig, api_secret: &Option<String>) -> Self {
        Self::new(
            config
                .global
                .api_endpoints
                .iter()
                .map(|(id, peer)| (*id, peer.url.clone()))
                .collect(),
            api_secret,
        )
    }

    pub fn with_self_peer_id(self, self_peer_id: PeerId) -> Self {
        Self {
            self_peer_id: Some(self_peer_id),
            ..self
        }
    }
}

impl<C> WsFederationApi<C>
where
    C: JsonRpcClient + 'static,
{
    pub fn peers(&self) -> Vec<PeerId> {
        self.peers.iter().map(|peer| peer.peer_id).collect()
    }

    /// Creates a new API client
    pub fn new_with_client(
        peers: Vec<(PeerId, SafeUrl)>,
        self_peer_id: Option<PeerId>,
        api_secret: &Option<String>,
    ) -> Self {
        WsFederationApi {
            peer_ids: peers.iter().map(|m| m.0).collect(),
            self_peer_id,
            peers: Arc::new(
                peers
                    .into_iter()
                    .map(|(peer_id, url)| {
                        assert!(
                            url.port_or_known_default().is_some(),
                            "API client requires a port"
                        );
                        assert!(url.host().is_some(), "API client requires a target host");

                        FederationPeer::new(url, peer_id, api_secret.clone())
                    })
                    .collect(),
            ),
            module_id: None,
        }
    }
}

#[derive(Debug)]
pub struct PeerResponse<R> {
    pub peer: PeerId,
    pub result: JsonRpcResult<R>,
}

impl<C> FederationPeer<C>
where
    C: JsonRpcClient + 'static,
{
    #[instrument(level = "trace", fields(peer = %self.peer_id, %method), skip_all)]
    pub async fn request(&self, method: &str, params: &[Value]) -> JsonRpcResult<Value> {
        for attempts in 0.. {
            debug_assert!(attempts <= 1);
            let rclient = self.client.read().await;
            match rclient.client.get_try().await {
                Ok(client) if client.is_connected() => {
                    return client.request::<_, _>(method, params).await;
                }
                Err(e) => {
                    // Strategies using timeouts often depend on failing requests returning quickly,
                    // so every request gets only one reconnection attempt.
                    if 0 < attempts {
                        return Err(JsonRpcClientError::Transport(e.into()));
                    }
                    debug!(target: LOG_CLIENT_NET_API, err=%e, "Triggering reconnection after connection error");
                }
                Ok(_client) => {
                    if 0 < attempts {
                        return Err(JsonRpcClientError::Transport(anyhow::format_err!(
                            "Disconnected"
                        )));
                    }
                    debug!(target: LOG_CLIENT_NET_API, "Triggering reconnection after disconnection");
                }
            };

            drop(rclient);
            let mut wclient = self.client.write().await;
            match wclient.client.get_try().await {
                Ok(client) if client.is_connected() => {
                    // someone else connected, just loop again
                    trace!(target: LOG_CLIENT_NET_API, "Some other request reconnected client, retrying");
                }
                _ => {
                    wclient.reconnect(self.peer_id, self.url.clone(), self.api_secret.clone());
                }
            }
        }

        unreachable!();
    }
}

impl<C: JsonRpcClient> WsFederationApi<C> {}

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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStatus {
    pub last_contribution: Option<u64>,
    pub connection_status: PeerConnectionStatus,
    /// Indicates that this peer needs attention from the operator since
    /// it has not contributed to the consensus in a long time
    pub flagged: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerConnectionStatus {
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
    use jsonrpsee_core::client::BatchResponse;
    use jsonrpsee_core::params::BatchRequestBuilder;
    use jsonrpsee_core::traits::ToRpcParams;

    use super::*;

    type Result<T = ()> = std::result::Result<T, JsonRpcClientError>;

    #[apply(async_trait_maybe_send!)]
    trait SimpleClient: Sized {
        async fn connect() -> Result<Self>;
        fn is_connected(&self) -> bool {
            true
        }
        // reply with json
        async fn request(&self, method: &str) -> Result<String>;
    }

    struct Client<C: SimpleClient>(C);

    #[apply(async_trait_maybe_send!)]
    impl<C: SimpleClient + MaybeSend + MaybeSync> JsonRpcClient for Client<C> {
        fn is_connected(&self) -> bool {
            self.0.is_connected()
        }

        async fn connect(_url: &SafeUrl, _api_secret: Option<String>) -> Result<Self> {
            Ok(Self(C::connect().await?))
        }
    }

    #[apply(async_trait_maybe_send!)]
    impl<C: SimpleClient + MaybeSend + MaybeSync> ClientT for Client<C> {
        async fn request<R, P>(&self, method: &str, _params: P) -> Result<R>
        where
            R: jsonrpsee_core::DeserializeOwned,
            P: ToRpcParams + MaybeSend,
        {
            let json = self.0.request(method).await?;
            Ok(serde_json::from_str(&json).unwrap())
        }

        async fn notification<P>(&self, _method: &str, _params: P) -> Result<()>
        where
            P: ToRpcParams + MaybeSend,
        {
            unimplemented!()
        }

        async fn batch_request<'a, R>(
            &self,
            _batch: BatchRequestBuilder<'a>,
        ) -> std::result::Result<BatchResponse<'a, R>, jsonrpsee_core::client::Error>
        where
            R: DeserializeOwned + fmt::Debug + 'a,
        {
            unimplemented!()
        }
    }

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
