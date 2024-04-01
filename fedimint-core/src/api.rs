use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{self, Debug, Display, Formatter};
use std::io::{Cursor, Read};
use std::num::NonZeroUsize;
use std::ops::Add;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, result};

use anyhow::{anyhow, ensure};
use bech32::Variant::Bech32m;
use bech32::{FromBase32, ToBase32};
use bitcoin::secp256k1;
use bitcoin_hashes::sha256;
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::core::{DynOutputOutcome, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::endpoint_constants::{
    AWAIT_SESSION_OUTCOME_ENDPOINT, SERVER_CONFIG_CONSENSUS_HASH_ENDPOINT,
};
use fedimint_core::fmt_utils::AbbreviateDebug;
use fedimint_core::module::SerdeModuleEncoding;
use fedimint_core::task::{MaybeSend, MaybeSync, RwLock, RwLockWriteGuard};
use fedimint_core::time::now;
use fedimint_core::{
    apply, async_trait_maybe_send, dyn_newtype_define, ModuleDecoderRegistry, NumPeersExt,
    OutPoint, PeerId, TransactionId,
};
use fedimint_logging::{LOG_CLIENT_NET_API, LOG_NET_API};
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use jsonrpsee_core::client::{ClientT, Error as JsonRpcClientError};
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::OnceCell;
use tracing::{debug, error, instrument, trace, warn};

use crate::admin_client::{
    ConfigGenConnectionsRequest, ConfigGenParamsRequest, ConfigGenParamsResponse, PeerServerParams,
};
use crate::backup::ClientBackupSnapshot;
use crate::core::backup::SignedBackupRequest;
use crate::core::{Decoder, OutputOutcome};
use crate::encoding::DecodeError;
use crate::endpoint_constants::{
    ADD_CONFIG_GEN_PEER_ENDPOINT, AUDIT_ENDPOINT, AUTH_ENDPOINT, AWAIT_OUTPUT_OUTCOME_ENDPOINT,
    AWAIT_TRANSACTION_ENDPOINT, BACKUP_ENDPOINT, CONFIG_GEN_PEERS_ENDPOINT,
    CONSENSUS_CONFIG_GEN_PARAMS_ENDPOINT, DEFAULT_CONFIG_GEN_PARAMS_ENDPOINT,
    GUARDIAN_CONFIG_BACKUP_ENDPOINT, RECOVER_ENDPOINT, RESTART_FEDERATION_SETUP_ENDPOINT,
    RUN_DKG_ENDPOINT, SESSION_COUNT_ENDPOINT, SESSION_STATUS_ENDPOINT,
    SET_CONFIG_GEN_CONNECTIONS_ENDPOINT, SET_CONFIG_GEN_PARAMS_ENDPOINT, SET_PASSWORD_ENDPOINT,
    START_CONSENSUS_ENDPOINT, STATUS_ENDPOINT, SUBMIT_TRANSACTION_ENDPOINT,
    VERIFIED_CONFIGS_ENDPOINT, VERIFY_CONFIG_HASH_ENDPOINT, VERSION_ENDPOINT,
};
use crate::module::audit::AuditSummary;
use crate::module::{ApiAuth, ApiRequestErased, ApiVersion, SupportedApiVersionsSummary};
use crate::query::{
    DiscoverApiVersionSet, QueryStep, QueryStrategy, ThresholdConsensus, UnionResponsesSingle,
};
use crate::session_outcome::{AcceptedItem, SessionOutcome, SessionStatus};
use crate::task;
use crate::transaction::{SerdeTransaction, Transaction, TransactionError};
use crate::util::SafeUrl;

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
            PeerError::ResponseDeserialization(_) => true,
            PeerError::InvalidPeerId { peer_id: _ } => true,
            PeerError::Rpc(rpc_e) => match rpc_e {
                // TODO: Does this cover all retryable cases?
                JsonRpcClientError::Transport(_) => false,
                JsonRpcClientError::MaxSlotsExceeded => true,
                JsonRpcClientError::RequestTimeout => false,
                JsonRpcClientError::RestartNeeded(_) => true,
                JsonRpcClientError::Call(_) => true,
                JsonRpcClientError::ParseError(_) => true,
                JsonRpcClientError::InvalidSubscriptionId => true,
                JsonRpcClientError::InvalidRequestId(_) => true,
                JsonRpcClientError::Custom(_) => true,
                JsonRpcClientError::HttpNotImplemented => true,
                JsonRpcClientError::EmptyBatchRequest(_) => true,
                JsonRpcClientError::RegisterMethod(_) => true,
            },
            PeerError::InvalidResponse(_) => true,
        };

        trace!(target: LOG_CLIENT_NET_API, error = %self, "PeerError");

        if important {
            warn!(target: LOG_CLIENT_NET_API, error = %self, %peer_id, "Unusual PeerError")
        }
    }
}

/// An API request error when calling an entire federation
///
/// Generally all Federation errors are retriable.
#[derive(Debug, Error)]
pub struct FederationError {
    general: Option<anyhow::Error>,
    peers: BTreeMap<PeerId, PeerError>,
}

impl Display for FederationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Federation rpc error {")?;
        if let Some(general) = self.general.as_ref() {
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
    pub fn general(e: impl Into<anyhow::Error>) -> FederationError {
        FederationError {
            general: Some(e.into()),
            peers: Default::default(),
        }
    }

    /// Report any errors
    pub fn report_if_important(&self) {
        if let Some(error) = self.general.as_ref() {
            warn!(target: LOG_CLIENT_NET_API, %error, "General FederationError");
        }
        for (peer_id, e) in &self.peers {
            e.report_if_important(*peer_id)
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
            OutputOutcomeError::ResponseDeserialization(_) => true,
            OutputOutcomeError::Federation(e) => {
                e.report_if_important();
                return;
            }
            OutputOutcomeError::Core(_) => true,
            OutputOutcomeError::Rejected(_) => false,
            OutputOutcomeError::InvalidVout {
                out_idx: _,
                outputs_num: _,
            } => true,
            OutputOutcomeError::Timeout(_) => false,
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
            match fedimint_core::task::timeout(timeout, request).await {
                Ok(result) => result,
                Err(_timeout) => Err(JsonRpcClientError::RequestTimeout),
            }
        } else {
            request.await
        }
    }

    /// Make an aggregate request to federation, using `strategy` to logically
    /// merge the responses.
    async fn request_with_strategy<PeerRet: serde::de::DeserializeOwned, FedRet: Debug>(
        &self,
        mut strategy: impl QueryStrategy<PeerRet, FedRet> + MaybeSend,
        method: String,
        params: ApiRequestErased,
    ) -> FederationResult<FedRet> {
        let timeout = strategy.request_timeout();

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

                let result = if let Some(timeout) = timeout {
                    match fedimint_core::task::timeout(timeout, request).await {
                        Ok(result) => result,
                        Err(_timeout) => Err(JsonRpcClientError::RequestTimeout),
                    }
                } else {
                    request.await
                };

                PeerResponse {
                    peer: *peer_id,
                    result,
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
                                        task::sleep(Duration::from_millis(delay_ms)).await;
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
                            return Err(FederationError { general, peers })
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
            ThresholdConsensus::new(self.all_peers().total()),
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
        // We would never want to accidentally send our password to everyone
        assert_eq!(
            self.all_peers().len(),
            1,
            "attempted to broadcast admin password?!"
        );
        self.request_current_consensus(method.into(), params.with_auth(auth))
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
        // There is no auth involved, but still - it should only ever be called on a
        // single endpoint
        assert_eq!(
            self.all_peers().len(),
            1,
            "attempted to broadcast an admin request?!"
        );
        self.request_current_consensus(method.into(), params).await
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
    pub fn from_pre_peer_id_endpoint(url: SafeUrl) -> Self {
        // PeerIds are used only for informational purposes, but just in case, make a
        // big number so it stands out
        GlobalFederationApiWithCache::new(WsFederationApi::new(vec![(PeerId::from(1024), url)]))
            .into()
    }

    pub fn from_single_endpoint(peer: PeerId, url: SafeUrl) -> Self {
        GlobalFederationApiWithCache::new(WsFederationApi::new(vec![(peer, url)])).into()
    }
    pub fn from_endpoints(peers: Vec<(PeerId, SafeUrl)>) -> Self {
        GlobalFederationApiWithCache::new(WsFederationApi::new(peers)).into()
    }

    pub fn from_config(config: &ClientConfig) -> Self {
        GlobalFederationApiWithCache::new(WsFederationApi::from_config(config)).into()
    }

    pub fn from_invite_code(invite_code: &[InviteCode]) -> Self {
        GlobalFederationApiWithCache::new(WsFederationApi::from_invite_code(invite_code)).into()
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
        fedimint_core::task::timeout(timeout, async move {
            let outcome: SerdeOutputOutcome = self
                .inner
                .request_current_consensus(
                    AWAIT_OUTPUT_OUTCOME_ENDPOINT.to_owned(),
                    ApiRequestErased::new(outpoint),
                )
                .await
                .map_err(OutputOutcomeError::Federation)?;

            deserialize_outcome(outcome, module_decoder)
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
    ) -> FederationResult<SerdeModuleEncoding<Result<TransactionId, TransactionError>>>;

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
    ) -> FederationResult<Vec<ClientBackupSnapshot>>;

    /// Query peers and calculate optimal common api versions to use.
    async fn discover_api_version_set(
        &self,
        client_versions: &SupportedApiVersionsSummary,
        timeout: Duration,
        num_responses_required: Option<usize>,
    ) -> FederationResult<ApiVersionSet>;

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
    outcome: SerdeOutputOutcome,
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
    #[allow(clippy::type_complexity)]
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
        .try_into_inner(decoders)
        .map_err(|e| anyhow!(e.to_string()))
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
    ) -> FederationResult<SerdeModuleEncoding<Result<TransactionId, TransactionError>>> {
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
    ) -> FederationResult<Vec<ClientBackupSnapshot>> {
        Ok(self
            .request_with_strategy(
                UnionResponsesSingle::<Option<ClientBackupSnapshot>>::new(self.all_peers().total()),
                RECOVER_ENDPOINT.to_owned(),
                ApiRequestErased::new(id),
            )
            .await?
            .into_iter()
            .flatten()
            .collect())
    }

    async fn discover_api_version_set(
        &self,
        client_versions: &SupportedApiVersionsSummary,
        timeout: Duration,
        num_responses_required: Option<usize>,
    ) -> FederationResult<ApiVersionSet> {
        self.request_with_strategy(
            DiscoverApiVersionSet::new(
                num_responses_required
                    .unwrap_or(self.all_peers().len())
                    .min(self.all_peers().len()),
                now().add(timeout),
                client_versions.clone(),
            ),
            VERSION_ENDPOINT.to_owned(),
            ApiRequestErased::default(),
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
    peers: Arc<Vec<FederationPeer<C>>>,
    module_id: Option<ModuleInstanceId>,
}

#[derive(Debug)]
struct FederationPeer<C> {
    url: SafeUrl,
    peer_id: PeerId,
    client: RwLock<Option<C>>,
}

/// Information required for client to construct [`WsFederationApi`] instance
///
/// Can be used to download the configs and bootstrap a client.
///
/// ## Invariants
/// Constructors have to guarantee that:
///   * At least one Api entry is present
///   * At least one Federation ID is present
#[derive(Clone, Debug, Eq, PartialEq, Encodable)]
pub struct InviteCode(Vec<InviteCodeData>);

impl Decodable for InviteCode {
    fn consensus_decode<R: Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let inner: Vec<InviteCodeData> = Decodable::consensus_decode(r, modules)?;

        if !inner
            .iter()
            .any(|data| matches!(data, InviteCodeData::Api { .. }))
        {
            return Err(DecodeError::from_str(
                "No API was provided in the invite code",
            ));
        }

        if !inner
            .iter()
            .any(|data| matches!(data, InviteCodeData::FederationId(_)))
        {
            return Err(DecodeError::from_str(
                "No Federation ID provided in invite code",
            ));
        }

        Ok(InviteCode(inner))
    }
}

impl InviteCode {
    pub fn new(url: SafeUrl, peer: PeerId, federation_id: FederationId) -> Self {
        InviteCode(vec![
            InviteCodeData::Api { url, peer },
            InviteCodeData::FederationId(federation_id),
        ])
    }

    /// Constructs an [`InviteCode`] which contains as many guardian URLs as
    /// needed to always be able to join a working federation
    pub fn new_with_essential_num_guardians(
        peer_to_url_map: &BTreeMap<PeerId, SafeUrl>,
        federation_id: FederationId,
    ) -> Self {
        let max_size = peer_to_url_map.max_evil() + 1;
        let mut code_vec: Vec<InviteCodeData> = peer_to_url_map
            .iter()
            .take(max_size)
            .map(|(peer, url)| InviteCodeData::Api {
                url: url.clone(),
                peer: *peer,
            })
            .collect();
        code_vec.push(InviteCodeData::FederationId(federation_id));

        InviteCode(code_vec)
    }

    /// Returns the API URL of one of the guardians.
    pub fn url(&self) -> SafeUrl {
        self.0
            .iter()
            .find_map(|data| match data {
                InviteCodeData::Api { url, .. } => Some(url.clone()),
                _ => None,
            })
            .expect("Ensured by constructor")
    }

    /// Returns the id of the guardian from which we got the API URL, see
    /// [`InviteCode::url`].
    pub fn peer(&self) -> PeerId {
        self.0
            .iter()
            .find_map(|data| match data {
                InviteCodeData::Api { peer, .. } => Some(*peer),
                _ => None,
            })
            .expect("Ensured by constructor")
    }

    /// Get all peer URLs in the [`InviteCode`]
    pub fn peers(&self) -> BTreeMap<PeerId, SafeUrl> {
        self.0
            .iter()
            .filter_map(|entry| match entry {
                InviteCodeData::Api { url, peer } => Some((*peer, url.clone())),
                _ => None,
            })
            .collect()
    }

    /// Returns the federation's ID that can be used to authenticate the config
    /// downloaded from the API.
    pub fn federation_id(&self) -> FederationId {
        self.0
            .iter()
            .find_map(|data| match data {
                InviteCodeData::FederationId(federation_id) => Some(*federation_id),
                _ => None,
            })
            .expect("Ensured by constructor")
    }
}

/// Data that can be encoded in the invite code. Currently we always just use
/// one `Api` and one `FederationId` variant in an invite code, but more can be
/// added in the future while still keeping the invite code readable for older
/// clients, which will just ignore the new fields.
#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable)]
enum InviteCodeData {
    /// API endpoint of one of the guardians
    Api {
        /// URL to reach an API that we can download configs from
        url: SafeUrl,
        /// Peer id of the host from the Url
        peer: PeerId,
    },
    /// Authentication id for the federation
    FederationId(FederationId),
    /// Unknown invite code fields to be defined in the future
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// We can represent client invite code as a bech32 string for compactness and
/// error-checking
///
/// Human readable part (HRP) includes the version
/// ```txt
/// [ hrp (4 bytes) ] [ id (48 bytes) ] ([ url len (2 bytes) ] [ url bytes (url len bytes) ])+
/// ```
const BECH32_HRP: &str = "fed1";

impl FromStr for InviteCode {
    type Err = anyhow::Error;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        let (hrp, data, variant) = bech32::decode(encoded)?;

        ensure!(hrp == BECH32_HRP, "Invalid HRP in bech32 encoding");
        ensure!(variant == Bech32m, "Expected Bech32m encoding");

        let bytes: Vec<u8> = Vec::<u8>::from_base32(&data)?;
        let invite = InviteCode::consensus_decode(&mut Cursor::new(bytes), &Default::default())?;

        Ok(invite)
    }
}

/// Parses the invite code from a bech32 string
impl Display for InviteCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut data = vec![];

        self.consensus_encode(&mut data)
            .expect("Vec<u8> provides capacity");

        let encode =
            bech32::encode(BECH32_HRP, data.to_base32(), Bech32m).map_err(|_| fmt::Error)?;
        formatter.write_str(&encode)
    }
}

impl Serialize for InviteCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        String::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for InviteCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = Cow::<str>::deserialize(deserializer)?;
        Self::from_str(&string).map_err(serde::de::Error::custom)
    }
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

    fn with_module(&self, id: ModuleInstanceId) -> DynModuleApi {
        WsFederationApi {
            peer_ids: self.peer_ids.clone(),
            peers: self.peers.clone(),
            module_id: Some(id),
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
    async fn connect(url: &SafeUrl) -> result::Result<Self, JsonRpcClientError>;
    fn is_connected(&self) -> bool;
}

#[apply(async_trait_maybe_send!)]
impl JsonRpcClient for WsClient {
    async fn connect(url: &SafeUrl) -> result::Result<Self, JsonRpcClientError> {
        #[cfg(not(target_family = "wasm"))]
        return WsClientBuilder::default()
            .use_webpki_rustls()
            .max_concurrent_requests(u16::MAX as usize)
            .build(url.as_str())
            .await;

        #[cfg(target_family = "wasm")]
        WsClientBuilder::default()
            .max_concurrent_requests(u16::MAX as usize)
            .build(url.as_str())
            .await
    }

    fn is_connected(&self) -> bool {
        self.is_connected()
    }
}

impl WsFederationApi<WsClient> {
    /// Creates a new API client
    pub fn new(peers: Vec<(PeerId, SafeUrl)>) -> Self {
        Self::new_with_client(peers)
    }

    /// Creates a new API client from a client config
    pub fn from_config(config: &ClientConfig) -> Self {
        Self::new(
            config
                .global
                .api_endpoints
                .iter()
                .map(|(id, peer)| (*id, peer.url.clone()))
                .collect(),
        )
    }

    /// Creates a new API client from a invite code, assumes they are in peer
    /// id order
    pub fn from_invite_code(info: &[InviteCode]) -> Self {
        Self::new(
            info.iter()
                .enumerate()
                .map(|(id, connect)| (PeerId::from(id as u16), connect.url()))
                .collect(),
        )
    }
}

impl<C> WsFederationApi<C> {
    pub fn peers(&self) -> Vec<PeerId> {
        self.peers.iter().map(|peer| peer.peer_id).collect()
    }

    /// Creates a new API client
    pub fn new_with_client(peers: Vec<(PeerId, SafeUrl)>) -> Self {
        WsFederationApi {
            peer_ids: peers.iter().map(|m| m.0).collect(),
            peers: Arc::new(
                peers
                    .into_iter()
                    .map(|(peer_id, url)| {
                        assert!(
                            url.port_or_known_default().is_some(),
                            "API client requires a port"
                        );
                        assert!(url.host().is_some(), "API client requires a target host");

                        FederationPeer {
                            peer_id,
                            url,
                            client: RwLock::new(None),
                        }
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

impl<C: JsonRpcClient> FederationPeer<C> {
    #[instrument(level = "trace", fields(peer = %self.peer_id, %method), skip_all)]
    pub async fn request(&self, method: &str, params: &[Value]) -> JsonRpcResult<Value> {
        let rclient = self.client.read().await;
        match &*rclient {
            Some(client) if client.is_connected() => {
                return client.request::<_, _>(method, params).await;
            }
            _ => {}
        };

        debug!("web socket not connected, reconnecting");

        drop(rclient);
        let mut wclient = self.client.write().await;
        Ok(match &*wclient {
            Some(client) if client.is_connected() => {
                // other task has already connected it
                let rclient = RwLockWriteGuard::downgrade(wclient);
                rclient
                    .as_ref()
                    .unwrap()
                    .request::<_, _>(method, params)
                    .await?
            }
            _ => {
                // write lock is acquired before creating a new client
                // so only one task will try to create a new client
                match C::connect(&self.url).await {
                    Ok(client) => {
                        *wclient = Some(client);
                        // drop the write lock before making the request
                        let rclient = RwLockWriteGuard::downgrade(wclient);
                        rclient
                            .as_ref()
                            .unwrap()
                            .request::<_, _>(method, params)
                            .await?
                    }
                    Err(err) => {
                        // Low logging level because we will probably retry connecting later
                        // we are going to retry, and a Federation peer being down is a fact
                        // of life, and nothing to warn about right away
                        debug!(
                            target: LOG_NET_API,
                            peer_id = %self.peer_id,
                            %err, "Unable to connect to peer");
                        return Err(err)?;
                    }
                }
            }
        })
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

/// The state of the server returned via APIs
#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ServerStatus {
    /// Server needs a password to read configs
    #[default]
    AwaitingPassword,
    /// Waiting for peers to share the config gen params
    SharingConfigGenParams,
    /// Ready to run config gen once all peers are ready
    ReadyForConfigGen,
    /// We failed running config gen
    ConfigGenFailed,
    /// Config is generated, peers should verify the config
    VerifyingConfigs,
    /// We have verified all our peer configs
    VerifiedConfigs,
    /// Consensus is running
    ConsensusRunning,
    /// Restarted setup. All peers need to sync on this state before continuing
    /// to `SharingConfigGenParams`
    SetupRestarted,
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
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use anyhow::anyhow;
    use jsonrpsee_core::client::BatchResponse;
    use jsonrpsee_core::params::BatchRequestBuilder;
    use jsonrpsee_core::traits::ToRpcParams;
    use once_cell::sync::Lazy;
    use serde::de::DeserializeOwned;
    use tracing::error;

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

        async fn connect(_url: &SafeUrl) -> Result<Self> {
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

    fn federation_peer<C: SimpleClient + MaybeSend + MaybeSync>() -> FederationPeer<Client<C>> {
        FederationPeer {
            url: SafeUrl::parse("http://127.0.0.1").expect("Could not parse"),
            peer_id: PeerId::from(0),
            client: RwLock::new(None),
        }
    }

    #[test_log::test(tokio::test)]
    async fn test_connect() {
        static CONNECTION_COUNT: AtomicUsize = AtomicUsize::new(0);
        static CONNECTED: AtomicBool = AtomicBool::new(true);
        struct Client;

        #[apply(async_trait_maybe_send!)]
        impl SimpleClient for Client {
            async fn connect() -> Result<Self> {
                CONNECTION_COUNT.fetch_add(1, Ordering::SeqCst);
                Ok(Client)
            }

            fn is_connected(&self) -> bool {
                CONNECTED.load(Ordering::SeqCst)
            }

            async fn request(&self, _method: &str) -> Result<String> {
                Ok("null".to_string())
            }
        }

        let fed = federation_peer::<Client>();
        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            0,
            "should not connect before first request"
        );

        fed.request("", &[]).await.unwrap();
        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            1,
            "should connect once after first request"
        );

        fed.request("", &[]).await.unwrap();
        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            1,
            "should not connect again before disconnect"
        );

        // disconnect
        CONNECTED.store(false, Ordering::SeqCst);

        fed.request("", &[]).await.unwrap();
        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            2,
            "should connect again after disconnect"
        );
    }

    #[test_log::test(tokio::test)]
    async fn concurrent_requests() {
        static CONNECTION_COUNT: AtomicUsize = AtomicUsize::new(0);
        static FAIL: Lazy<Mutex<HashSet<usize>>> = Lazy::new(|| Mutex::new(HashSet::new()));

        struct Client(usize);

        #[apply(async_trait_maybe_send!)]
        impl SimpleClient for Client {
            async fn connect() -> Result<Self> {
                error!(target: LOG_NET_API, "connect");
                let id = CONNECTION_COUNT.fetch_add(1, Ordering::SeqCst);
                // slow down
                task::sleep(Duration::from_millis(100)).await;
                if FAIL.lock().unwrap().contains(&id) {
                    Err(jsonrpsee_core::client::Error::Transport(anyhow!(
                        "intentional error"
                    )))
                } else {
                    Ok(Client(id))
                }
            }

            fn is_connected(&self) -> bool {
                !FAIL.lock().unwrap().contains(&self.0)
            }

            async fn request(&self, _method: &str) -> Result<String> {
                if self.is_connected() {
                    Ok("null".to_string())
                } else {
                    Err(jsonrpsee_core::client::Error::Transport(anyhow!(
                        "client is disconnected"
                    )))
                }
            }
        }

        let fed = federation_peer::<Client>();

        FAIL.lock().unwrap().insert(0);

        assert!(
            fed.request("", &[]).await.is_err(),
            "connect for client 0 should fail"
        );

        // connect for client 1 should succeed
        fed.request("", &[]).await.unwrap();

        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            2,
            "should connect again after error in first connect"
        );

        // force a new connection by disconnecting client 1
        FAIL.lock().unwrap().insert(1);

        // only connect once even for two concurrent requests
        let (reqa, reqb) = tokio::join!(fed.request("", &[]), fed.request("", &[]));
        reqa.expect("both request should be successful");
        reqb.expect("both request should be successful");

        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            3,
            "should connect once even for two concurrent requests",
        );

        // force a new connection by disconnecting client 2
        FAIL.lock().unwrap().insert(2);

        // client 3 should fail
        // client 4 should succeed
        FAIL.lock().unwrap().insert(3);

        // only connect once even for two concurrent requests
        let (reqa, reqb) = tokio::join!(fed.request("", &[]), fed.request("", &[]));

        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            5,
            "should connect again if first concurrent request fails",
        );

        assert!(
            reqa.is_err() ^ reqb.is_err(),
            "exactly one of two request should succeed"
        );
    }

    #[test]
    fn converts_invite_code() {
        let connect = InviteCode::new(
            "ws://test1".parse().unwrap(),
            PeerId(1),
            FederationId::dummy(),
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
        peer_to_url_map.insert(PeerId(0), "ws://test1".parse().expect("URL fail"));
        peer_to_url_map.insert(PeerId(1), "ws://test2".parse().expect("URL fail"));
        peer_to_url_map.insert(PeerId(2), "ws://test3".parse().expect("URL fail"));
        peer_to_url_map.insert(PeerId(3), "ws://test4".parse().expect("URL fail"));
        let max_size = peer_to_url_map.max_evil() + 1;

        let code =
            InviteCode::new_with_essential_num_guardians(&peer_to_url_map, FederationId::dummy());

        assert_eq!(FederationId::dummy(), code.federation_id());

        let expected_map: BTreeMap<PeerId, SafeUrl> =
            peer_to_url_map.into_iter().take(max_size).collect();
        assert_eq!(expected_map, code.peers());
    }
}
