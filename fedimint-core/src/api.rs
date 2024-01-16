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

use anyhow::{anyhow, bail, ensure};
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
    apply, async_trait_maybe_send, dyn_newtype_define, ModuleDecoderRegistry, NumPeers, OutPoint,
    PeerId, TransactionId,
};
use fedimint_logging::{LOG_CLIENT_NET_API, LOG_NET_API};
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use jsonrpsee_core::client::{ClientT, Error as JsonRpcClientError};
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tracing::{debug, error, instrument, trace};

use crate::backup::ClientBackupSnapshot;
use crate::core::backup::SignedBackupRequest;
use crate::core::{Decoder, OutputOutcome};
use crate::encoding::DecodeError;
use crate::endpoint_constants::{
    AWAIT_OUTPUT_OUTCOME_ENDPOINT, AWAIT_TRANSACTION_ENDPOINT, BACKUP_ENDPOINT,
    CLIENT_CONFIG_ENDPOINT, RECOVER_ENDPOINT, SESSION_COUNT_ENDPOINT, SUBMIT_TRANSACTION_ENDPOINT,
    VERSION_ENDPOINT,
};
use crate::module::{ApiRequestErased, ApiVersion, SupportedApiVersionsSummary};
use crate::query::{
    DiscoverApiVersionSet, FilterMap, QueryStep, QueryStrategy, ThresholdConsensus,
    UnionResponsesSingle,
};
use crate::session_outcome::SessionOutcome;
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
    pub fn is_retryable(&self) -> bool {
        match self {
            PeerError::ResponseDeserialization(_) => false,
            PeerError::InvalidPeerId { peer_id: _ } => false,
            PeerError::Rpc(rpc_e) => match rpc_e {
                // TODO: Does this cover all retryable cases?
                JsonRpcClientError::Transport(_) => true,
                JsonRpcClientError::MaxSlotsExceeded => true,
                JsonRpcClientError::RequestTimeout => true,
                JsonRpcClientError::RestartNeeded(_) => true,
                JsonRpcClientError::Call(e) => e.code() == 404,
                _ => false,
            },
            PeerError::InvalidResponse(_) => false,
        }
    }
}

/// An API request error when calling an entire federation
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

    pub fn is_retryable(&self) -> bool {
        self.peers.iter().any(|(_, e)| e.is_retryable())
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

/// An API (module or global) that can query a federation
#[apply(async_trait_maybe_send!)]
pub trait IFederationApi: Debug + MaybeSend + MaybeSync {
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
/// [`IFederationApi`].
#[apply(async_trait_maybe_send!)]
pub trait FederationApiExt: IFederationApi {
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
            ThresholdConsensus::overcome_evil(self.all_peers().total()),
            method,
            params,
        )
        .await
    }
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> FederationApiExt for T where T: IFederationApi {}

/// Trait marker for the module (non-global) endpoints
pub trait IModuleFederationApi: IFederationApi {}

dyn_newtype_define! {
    #[derive(Clone)]
    pub DynModuleApi(Arc<IModuleFederationApi>)
}

/// Trait marker for the global (non-module) endpoints
pub trait IGlobalFederationApi: IFederationApi {}

dyn_newtype_define! {
    #[derive(Clone)]
    pub DynGlobalApi(Arc<IGlobalFederationApi>)
}

impl AsRef<dyn IGlobalFederationApi + 'static> for DynGlobalApi {
    fn as_ref(&self) -> &(dyn IGlobalFederationApi + 'static) {
        self.inner.as_ref()
    }
}

/// The API for the global (non-module) endpoints
#[apply(async_trait_maybe_send!)]
pub trait GlobalFederationApi {
    async fn submit_transaction(
        &self,
        tx: Transaction,
    ) -> FederationResult<SerdeModuleEncoding<Result<TransactionId, TransactionError>>>;

    async fn await_block(
        &self,
        block_index: u64,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionOutcome>;

    async fn session_count(&self) -> FederationResult<u64>;

    async fn await_transaction(&self, txid: TransactionId) -> FederationResult<TransactionId>;

    async fn await_output_outcome<R>(
        &self,
        outpoint: OutPoint,
        timeout: Duration,
        module_decoder: &Decoder,
    ) -> OutputOutcomeResult<R>
    where
        R: OutputOutcome;

    /// Fetch client configuration info only if verified against a federation id
    async fn download_client_config(&self, info: &InviteCode) -> FederationResult<ClientConfig>;

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
    ) -> FederationResult<ApiVersionSet>;
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

lazy_static! {
    /// Small LRU used as `GlobalFederatinApi::await_block` cache.
    ///
    /// This is mostly to avoid multiple client module recovery processes
    /// re-requesting same blocks and putting burden on the federation.
    ///
    /// The LRU can be be fairly small, as if the modules are (near-)bottlenecked
    /// on fetching blocks they will naturally synchronize, or split into
    /// a handful of groups. And if they are not, no LRU here is going to help
    /// them.
    static ref API_AWAIT_BLOCK_LRU: tokio::sync::Mutex<lru::LruCache<u64, Arc<tokio::sync::Mutex<Option<SessionOutcome>>>>> =
        tokio::sync::Mutex::new(lru::LruCache::new(
            NonZeroUsize::new(32).expect("is non-zero")
        ));
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> GlobalFederationApi for T
where
    T: IGlobalFederationApi + MaybeSend + MaybeSync + 'static,
{
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

    async fn await_block(
        &self,
        block_index: u64,
        decoders: &ModuleDecoderRegistry,
    ) -> anyhow::Result<SessionOutcome> {
        let mut lru_lock = API_AWAIT_BLOCK_LRU.lock().await;

        let block_entry_arc = lru_lock
            .get_or_insert(block_index, || Arc::new(tokio::sync::Mutex::new(None)))
            .clone();

        // we drop the lru lock so requests for other `block_index` can work in parallel
        drop(lru_lock);

        // but multiple request for the same `block_index` will serialize on the
        // per-index lock, avoiding doing the same work
        let mut block_lock = block_entry_arc.lock().await;

        if let Some(cached_res) = block_lock.clone() {
            debug!(block_index, "Using a cached await_block response");
            return Ok(cached_res);
        }

        let block = self
            .request_current_consensus::<SerdeModuleEncoding<SessionOutcome>>(
                AWAIT_SESSION_OUTCOME_ENDPOINT.to_string(),
                ApiRequestErased::new(block_index),
            )
            .await?
            .try_into_inner(decoders)
            .map_err(|e| anyhow!(e.to_string()))?;

        *block_lock = Some(block.clone());

        Ok(block)
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

    // TODO should become part of the API
    async fn await_output_outcome<R>(
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

    async fn download_client_config(
        &self,
        invite_code: &InviteCode,
    ) -> FederationResult<ClientConfig> {
        // we have to download the api endpoints first
        let id = invite_code.federation_id();
        let qs = FilterMap::new(
            move |cfg: ClientConfig| {
                if id.0 != cfg.global.api_endpoints.consensus_hash() {
                    bail!("Guardian api endpoint map does not hash to FederationId")
                }

                Ok(cfg.global.api_endpoints)
            },
            self.all_peers().total(),
        )
        // downloading the endpoints shouldn't take too long
        .with_request_timeout(Duration::from_secs(5));

        let api_endpoints = self
            .request_with_strategy(
                qs,
                CLIENT_CONFIG_ENDPOINT.to_owned(),
                ApiRequestErased::default(),
            )
            .await?;

        // now we can build an api for all guardians and download the client config
        let api_endpoints = api_endpoints
            .into_iter()
            .map(|(peer, url)| (peer, url.url))
            .collect();

        WsFederationApi::new(api_endpoints)
            .request_current_consensus(
                CLIENT_CONFIG_ENDPOINT.to_owned(),
                ApiRequestErased::default(),
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
    ) -> FederationResult<ApiVersionSet> {
        let timeout = Duration::from_secs(60);
        self.request_with_strategy(
            DiscoverApiVersionSet::new(
                self.all_peers().len(),
                now().add(timeout),
                client_versions.clone(),
            ),
            VERSION_ENDPOINT.to_owned(),
            ApiRequestErased::default(),
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

impl<C: JsonRpcClient + Debug + 'static> IGlobalFederationApi for WsFederationApi<C> {}

impl<C: JsonRpcClient + Debug + 'static> IModuleFederationApi for WsFederationApi<C> {}

/// Implementation of API calls over websockets
///
/// Can function as either the global or module API
#[apply(async_trait_maybe_send!)]
impl<C: JsonRpcClient + Debug + 'static> IFederationApi for WsFederationApi<C> {
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fmt;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

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
}
