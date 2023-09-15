use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{self, Debug, Display, Formatter};
use std::io::{Cursor, Read};
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
use fedimint_core::config::{ClientConfig, ClientConfigResponse, FederationId};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::encoding::Encodable;
use fedimint_core::fmt_utils::AbbreviateDebug;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{MaybeSend, MaybeSync, RwLock, RwLockWriteGuard};
use fedimint_core::time::now;
use fedimint_core::{
    apply, async_trait_maybe_send, dyn_newtype_define, NumPeers, OutPoint, PeerId, TransactionId,
};
use fedimint_derive::Decodable;
use fedimint_logging::{LOG_CLIENT_NET_API, LOG_NET_API};
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use jsonrpsee_core::client::ClientT;
use jsonrpsee_core::Error as JsonRpcError;
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use threshold_crypto::{PublicKey, PK_SIZE};
use tracing::{debug, error, instrument, trace, warn};

use crate::backup::ClientBackupSnapshot;
use crate::core::backup::SignedBackupRequest;
use crate::core::{Decoder, OutputOutcome};
use crate::epoch::{SerdeEpochHistory, SignedEpochOutcome};
use crate::module::{ApiRequestErased, ApiVersion, SupportedApiVersionsSummary};
use crate::outcome::{SerdeOutputOutcome, TransactionStatus};
use crate::query::{
    DiscoverApiVersionSet, QueryStep, QueryStrategy, ThresholdConsensus, UnionResponsesSingle,
    VerifiableResponse,
};
use crate::transaction::{SerdeTransaction, Transaction};
use crate::util::SafeUrl;
use crate::{serde_as_encodable_hex, task};

pub type PeerResult<T> = Result<T, PeerError>;
pub type JsonRpcResult<T> = Result<T, jsonrpsee_core::Error>;
pub type FederationResult<T> = Result<T, FederationError>;

/// An API request error when calling a single federation peer
#[derive(Debug, Error)]
pub enum PeerError {
    #[error("Response deserialization error: {0}")]
    ResponseDeserialization(anyhow::Error),
    #[error("Invalid peer id: {peer_id}")]
    InvalidPeerId { peer_id: PeerId },
    #[error("Rpc error: {0}")]
    Rpc(#[from] JsonRpcError),
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
                JsonRpcError::Transport(_) => true,
                JsonRpcError::MaxSlotsExceeded => true,
                JsonRpcError::RequestTimeout => true,
                JsonRpcError::Call(e) => e.code() == 404,
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
    ) -> result::Result<Value, jsonrpsee_core::Error>;
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
                        Err(_timeout) => Err(JsonRpcError::RequestTimeout),
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
    async fn submit_transaction(&self, tx: Transaction) -> FederationResult<TransactionId>;
    async fn fetch_tx_outcome(
        &self,
        txid: &TransactionId,
    ) -> FederationResult<Option<TransactionStatus>>;
    async fn await_tx_outcome(&self, txid: &TransactionId) -> FederationResult<TransactionStatus>;

    async fn fetch_epoch_history(
        &self,
        epoch: u64,
        epoch_pk: PublicKey,
        decoders: &ModuleDecoderRegistry,
    ) -> FederationResult<SignedEpochOutcome>;

    async fn fetch_epoch_count(&self) -> FederationResult<u64>;

    async fn fetch_output_outcome<R>(
        &self,
        out_point: OutPoint,
        module_decoder: &Decoder,
    ) -> OutputOutcomeResult<Option<R>>
    where
        R: OutputOutcome;

    async fn await_transaction(&self, txid: TransactionId) -> FederationResult<()>;

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
    async fn consensus_config_hash(&self) -> FederationResult<sha256::Hash>;

    async fn upload_backup(&self, request: &SignedBackupRequest) -> FederationResult<()>;

    async fn download_backup(
        &self,
        id: &secp256k1::XOnlyPublicKey,
    ) -> FederationResult<Vec<ClientBackupSnapshot>>;

    /// Query peers and calculate optimal common api versions to use.
    async fn discover_api_version_set(
        &self,
        client_versions: &SupportedApiVersionsSummary,
    ) -> FederationResult<ApiVersionSet>;
}

// TODO: this can be removed with the legacy client
fn map_tx_outcome_outpoint<R>(
    tx_outcome: TransactionStatus,
    out_point: OutPoint,
    module_decoder: &Decoder,
) -> OutputOutcomeResult<R>
where
    R: OutputOutcome + MaybeSend,
{
    match tx_outcome {
        TransactionStatus::Rejected(e) => Err(OutputOutcomeError::Rejected(e)),
        TransactionStatus::Accepted { outputs, .. } => {
            let outputs_len = outputs.len();

            outputs
                .into_iter()
                .nth(out_point.out_idx as usize) // avoid clone as would be necessary with .get(…)
                .ok_or(OutputOutcomeError::InvalidVout {
                    outputs_num: outputs_len,
                    out_idx: out_point.out_idx,
                })
                .and_then(|output| deserialize_outcome(output, module_decoder))
        }
    }
}

fn deserialize_outcome<R>(
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

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> GlobalFederationApi for T
where
    T: IGlobalFederationApi + MaybeSend + MaybeSync + 'static,
{
    /// Submit a transaction for inclusion
    async fn submit_transaction(&self, tx: Transaction) -> FederationResult<TransactionId> {
        self.request_current_consensus(
            "transaction".to_owned(),
            ApiRequestErased::new(&SerdeTransaction::from(&tx)),
        )
        .await
    }

    /// Fetch the outcome of an entire transaction
    async fn fetch_tx_outcome(
        &self,
        tx: &TransactionId,
    ) -> FederationResult<Option<TransactionStatus>> {
        self.request_current_consensus("fetch_transaction".to_owned(), ApiRequestErased::new(tx))
            .await
    }

    // TODO: this can be removed with the legacy client
    /// Await the outcome of an entire transaction
    async fn await_tx_outcome(&self, tx: &TransactionId) -> FederationResult<TransactionStatus> {
        self.request_current_consensus("wait_transaction".to_owned(), ApiRequestErased::new(tx))
            .await
    }

    async fn fetch_epoch_history(
        &self,
        epoch: u64,
        epoch_pk: PublicKey,
        decoders: &ModuleDecoderRegistry,
    ) -> FederationResult<SignedEpochOutcome> {
        // TODO: make this function avoid clone
        let decoders = decoders.clone();

        struct ValidHistoryWrapper {
            decoders: ModuleDecoderRegistry,
            strategy: VerifiableResponse<SignedEpochOutcome>,
        }

        impl QueryStrategy<SerdeEpochHistory, SignedEpochOutcome> for ValidHistoryWrapper {
            fn process(
                &mut self,
                peer: PeerId,
                result: PeerResult<SerdeEpochHistory>,
            ) -> QueryStep<SignedEpochOutcome> {
                let response = result.and_then(|hist| {
                    hist.try_into_inner(&self.decoders)
                        .map_err(|e| PeerError::Rpc(jsonrpsee_core::Error::Custom(e.to_string())))
                });
                match self.strategy.process(peer, response) {
                    QueryStep::Retry(r) => QueryStep::Retry(r),
                    QueryStep::Continue => QueryStep::Continue,
                    QueryStep::Success(res) => QueryStep::Success(res),
                    QueryStep::Failure { general, peers } => QueryStep::Failure { general, peers },
                }
            }
        }

        let qs = ValidHistoryWrapper {
            decoders,
            strategy: VerifiableResponse::new(
                move |epoch: &SignedEpochOutcome| epoch.verify_sig(&epoch_pk).is_ok(),
                true,
                self.all_peers().total(),
            ),
        };

        self.request_with_strategy::<SerdeEpochHistory, _>(
            qs,
            "fetch_epoch_history".to_owned(),
            ApiRequestErased::new(epoch),
        )
        .await
    }

    async fn fetch_epoch_count(&self) -> FederationResult<u64> {
        self.request_current_consensus("fetch_epoch_count".to_owned(), ApiRequestErased::default())
            .await
    }

    // TODO: this can be removed with the legacy client
    async fn fetch_output_outcome<R>(
        &self,
        out_point: OutPoint,
        module_decoder: &Decoder,
    ) -> OutputOutcomeResult<Option<R>>
    where
        R: OutputOutcome,
    {
        Ok(self
            .fetch_tx_outcome(&out_point.txid)
            .await?
            .map(move |tx_outcome| map_tx_outcome_outpoint(tx_outcome, out_point, module_decoder))
            .transpose()?)
    }

    async fn await_transaction(&self, txid: TransactionId) -> FederationResult<()> {
        self.request_current_consensus("await_transaction".to_owned(), ApiRequestErased::new(txid))
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
                    "await_output_outcome".to_owned(),
                    ApiRequestErased::new(outpoint),
                )
                .await
                .map_err(OutputOutcomeError::Federation)?;

            deserialize_outcome(outcome, module_decoder)
        })
        .await
        .map_err(|_| OutputOutcomeError::Timeout(timeout))?
    }

    async fn download_client_config(&self, info: &InviteCode) -> FederationResult<ClientConfig> {
        let id = info.id;
        let qs = VerifiableResponse::new(
            move |config: &ClientConfigResponse| {
                let hash = config.client_config.consensus_hash();
                id.0.verify(&config.signature.0, hash)
            },
            false,
            self.all_peers().total(),
        )
        // downloading a config shouldn't take too long
        .with_request_timeout(Duration::from_secs(5));

        self.request_with_strategy(
            qs,
            "config".to_owned(),
            ApiRequestErased::new(info.to_string()),
        )
        .await
        .map(|cfg: ClientConfigResponse| cfg.client_config)
    }

    async fn consensus_config_hash(&self) -> FederationResult<sha256::Hash> {
        self.request_current_consensus("config_hash".to_owned(), ApiRequestErased::default())
            .await
    }

    async fn upload_backup(&self, request: &SignedBackupRequest) -> FederationResult<()> {
        self.request_with_strategy(
            ThresholdConsensus::new(self.all_peers().total()),
            "backup".to_owned(),
            ApiRequestErased::new(request),
        )
        .await
    }

    async fn download_backup(
        &self,
        id: &secp256k1::XOnlyPublicKey,
    ) -> FederationResult<Vec<ClientBackupSnapshot>> {
        Ok(self
            .request_with_strategy(
                UnionResponsesSingle::<Option<ClientBackupSnapshot>>::new(self.all_peers().total()),
                "recover".to_owned(),
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
            "version".to_owned(),
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
/// Can be used to download the configs and bootstrap a client
#[derive(Clone, Debug, Eq, PartialEq, Encodable)]
pub struct InviteCode {
    /// URL to reach an API that we can download configs from
    pub url: SafeUrl,
    /// Config download token (might only be used a certain number of times)
    pub download_token: ClientConfigDownloadToken,
    /// Authentication id for the federation
    pub id: FederationId,
}

/// Size of a download token
const CONFIG_DOWNLOAD_TOKEN_BYTES: usize = 12;

/// Allows a client to download the config
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, PartialOrd, Ord)]
pub struct ClientConfigDownloadToken(pub [u8; CONFIG_DOWNLOAD_TOKEN_BYTES]);

serde_as_encodable_hex!(ClientConfigDownloadToken);

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
        let mut cursor = Cursor::new(bytes);
        let mut id_bytes = [0; PK_SIZE];
        cursor.read_exact(&mut id_bytes)?;

        let mut url_len = [0; 2];
        cursor.read_exact(&mut url_len)?;
        let url_len = u16::from_be_bytes(url_len).into();
        let mut url_bytes = vec![0; url_len];
        cursor.read_exact(&mut url_bytes)?;
        let mut download_token = [0; CONFIG_DOWNLOAD_TOKEN_BYTES];
        cursor.read_exact(&mut download_token)?;

        let url = std::str::from_utf8(&url_bytes)?;

        Ok(Self {
            url: url.parse()?,
            download_token: ClientConfigDownloadToken(download_token),
            id: FederationId(PublicKey::from_bytes(id_bytes)?),
        })
    }
}

/// Parses the invite code from a bech32 string
impl Display for InviteCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut data = vec![];
        data.extend(self.id.0.to_bytes());
        let url_bytes = self.url.as_str().as_bytes();
        data.extend((url_bytes.len() as u16).to_be_bytes());
        data.extend(url_bytes);
        data.extend(&self.download_token.0);
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
            .ok_or_else(|| JsonRpcError::Custom(format!("Invalid peer_id: {peer_id}")))?;

        let method = match self.module_id {
            None => method.to_string(),
            Some(id) => format!("module_{id}_{method}"),
        };
        peer.request(&method, params).await
    }
}

#[apply(async_trait_maybe_send!)]
pub trait JsonRpcClient: ClientT + Sized + MaybeSend + MaybeSync {
    async fn connect(url: &SafeUrl) -> result::Result<Self, JsonRpcError>;
    fn is_connected(&self) -> bool;
}

#[apply(async_trait_maybe_send!)]
impl JsonRpcClient for WsClient {
    async fn connect(url: &SafeUrl) -> result::Result<Self, JsonRpcError> {
        #[cfg(not(target_family = "wasm"))]
        return WsClientBuilder::default()
            .use_webpki_rustls()
            .build(url_to_string_with_default_port(url)) // Hack for default ports, see fn docs
            .await;

        #[cfg(target_family = "wasm")]
        WsClientBuilder::default()
            .build(url_to_string_with_default_port(url)) // Hack for default ports, see fn docs
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
                .map(|(id, connect)| (PeerId::from(id as u16), connect.url.clone()))
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
                        // Warn instead of Error because we will probably retry connecting later
                        warn!(
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

/// `jsonrpsee` converts the `SafeUrl` to a `&str` internally and then parses it
/// as an `Uri`. Unfortunately the underlying `Url` type swallows ports that it
/// considers default ports (e.g. 80 and 443 for HTTP(S)) which makes the `Uri`
/// parsing fail in these cases. This function works around this limitation in a
/// limited way (not fully standard compliant, but work for our use case).
///
/// See <https://github.com/paritytech/jsonrpsee/issues/554#issue-1048646896>
fn url_to_string_with_default_port(url: &SafeUrl) -> String {
    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host().expect("Asserted on construction"),
        url.port_or_known_default()
            .expect("Asserted on construction"),
        url.path()
    )
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
pub enum PeerConnectionStatus {
    #[default]
    Disconnected,
    Connected,
}

/// The state of the server returned via APIs
#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq, PartialEq)]
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
    /// Restarted from a planned upgrade (requires action to start)
    Upgrading,
    /// Consensus is running
    ConsensusRunning,
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
    use rand::rngs::OsRng;
    use rand::Rng;
    use serde::de::DeserializeOwned;
    use tracing::error;

    use super::*;

    type Result<T = ()> = std::result::Result<T, JsonRpcError>;

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
        ) -> std::result::Result<BatchResponse<'a, R>, jsonrpsee_core::Error>
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
                    Err(jsonrpsee_core::Error::Transport(anyhow!(
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
                    Err(jsonrpsee_core::Error::Transport(anyhow!(
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
        let connect = InviteCode {
            url: "ws://test1".parse().unwrap(),
            id: FederationId::dummy(),
            download_token: ClientConfigDownloadToken(OsRng.gen()),
        };

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
