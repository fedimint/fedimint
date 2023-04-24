use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Display, Formatter};
use std::io::{Cursor, Read};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, result};

use anyhow::{anyhow, ensure};
use bech32::Variant::Bech32m;
use bech32::{FromBase32, ToBase32};
use bitcoin_hashes::sha256;
use fedimint_core::config::{ClientConfig, CommonModuleGenRegistry, ConfigResponse, FederationId};
use fedimint_core::encoding::Encodable;
use fedimint_core::fmt_utils::AbbreviateDebug;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{sleep, MaybeSend, MaybeSync, RwLock, RwLockWriteGuard};
use fedimint_core::{
    apply, async_trait_maybe_send, dyn_newtype_define, NumPeers, OutPoint, PeerId, TransactionId,
};
use fedimint_derive::Decodable;
use fedimint_logging::LOG_NET_API;
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
use tracing::{debug, error, instrument, trace};
use url::Url;

use crate::core::{Decoder, OutputOutcome};
use crate::epoch::{SerdeEpochHistory, SignedEpochOutcome};
use crate::module::ApiRequestErased;
use crate::outcome::TransactionStatus;
use crate::query::{
    CurrentConsensus, EventuallyConsistent, QueryStep, QueryStrategy, UnionResponses,
    VerifiableResponse,
};
use crate::transaction::{SerdeTransaction, Transaction};

pub type MemberResult<T> = result::Result<T, MemberError>;

pub type JsonRpcResult<T> = result::Result<T, jsonrpsee_core::Error>;
pub type FederationResult<T> = result::Result<T, FederationError>;

/// An API request error when calling a single federation member
#[derive(Debug, Error)]
pub enum MemberError {
    #[error("Response deserialization error: {0}")]
    ResponseDeserialization(anyhow::Error),
    #[error("Invalid peer id: {peer_id}")]
    InvalidPeerId { peer_id: PeerId },
    #[error("Rpc error: {0}")]
    Rpc(#[from] JsonRpcError),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

impl MemberError {
    pub fn is_retryable(&self) -> bool {
        match self {
            MemberError::ResponseDeserialization(_) => false,
            MemberError::InvalidPeerId { peer_id: _ } => false,
            MemberError::Rpc(rpc_e) => match rpc_e {
                // TODO: Does this cover all retryable cases?
                JsonRpcError::Transport(_) => true,
                JsonRpcError::MaxSlotsExceeded => true,
                JsonRpcError::RequestTimeout => true,
                JsonRpcError::Call(e) => e.code() == 404,
                _ => false,
            },
            MemberError::InvalidResponse(_) => false,
        }
    }
}

/// An API request error when calling an entire federation
#[derive(Debug, Error)]
pub struct FederationError(BTreeMap<PeerId, MemberError>);

impl fmt::Display for FederationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Federation rpc error(")?;
        for (i, (peer, e)) in self.0.iter().enumerate() {
            f.write_fmt(format_args!("{peer} => {e})"))?;
            if i == self.0.len() - 1 {
                f.write_str(", ")?;
            }
        }
        f.write_str(")")?;
        Ok(())
    }
}

impl FederationError {
    pub fn is_retryable(&self) -> bool {
        self.0.iter().any(|(_, e)| e.is_retryable())
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

#[apply(async_trait_maybe_send!)]
pub trait IFederationApi: Debug + MaybeSend + MaybeSync {
    /// List of all federation members for the purpose of iterating each member
    /// in the federation.
    ///
    /// The underlying implementation is resonsible for knowing how many
    /// and `PeerId`s of each. The caller of this interface most probably
    /// have some idea as well, but passing this set across every
    /// API call to the federation would be inconvenient.
    fn all_members(&self) -> &BTreeSet<PeerId>;

    /// Make request to a specific federation member by `peer_id`
    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &[Value],
    ) -> result::Result<Value, jsonrpsee_core::Error>;
}

/// An extension trait allowing to making federation-wide API call on top
/// [`IFederationApi`].
#[apply(async_trait_maybe_send!)]
pub trait FederationApiExt: IFederationApi {
    /// Make an aggregate request to federation, using `strategy` to logically
    /// merge the responses.
    async fn request_with_strategy<MemberRet: serde::de::DeserializeOwned, FedRet: Debug>(
        &self,
        mut strategy: impl QueryStrategy<MemberRet, FedRet> + MaybeSend,
        method: String,
        params: ApiRequestErased,
    ) -> FederationResult<FedRet> {
        #[cfg(not(target_family = "wasm"))]
        let mut futures = FuturesUnordered::<Pin<Box<dyn Future<Output = _> + Send>>>::new();
        #[cfg(target_family = "wasm")]
        let mut futures = FuturesUnordered::<Pin<Box<dyn Future<Output = _>>>>::new();

        let peers = self.all_members();

        for peer_id in peers {
            futures.push(Box::pin(async {
                PeerResponse {
                    peer: *peer_id,
                    result: self
                        .request_raw(*peer_id, &method, &[params.to_json()])
                        .await
                        .map(AbbreviateDebug),
                }
            }));
        }

        let mut member_delay_ms = BTreeMap::new();
        let mut member_errors = BTreeMap::new();

        // Delegates the response handling to the `QueryStrategy` with an exponential
        // back-off with every new set of requests
        let max_delay_ms = 1000;
        loop {
            let response = futures.next().await;
            trace!(?response, method, params = ?AbbreviateDebug(params.to_json()), "Received member response");
            match response {
                Some(PeerResponse { peer, result }) => {
                    let result: MemberResult<MemberRet> =
                        result.map_err(MemberError::Rpc).and_then(|o| {
                            serde_json::from_value::<MemberRet>(o.0)
                                .map_err(|e| MemberError::ResponseDeserialization(e.into()))
                        });

                    let strategy_step = strategy.process(peer, result);
                    trace!(
                        method,
                        ?params,
                        ?strategy_step,
                        "Taking strategy step to the response after member response"
                    );
                    match strategy_step {
                        QueryStep::RetryMembers(peers) => {
                            for retry_peer in peers {
                                member_errors.remove(&retry_peer);

                                let mut delay_ms =
                                    member_delay_ms.get(&retry_peer).copied().unwrap_or(10);
                                delay_ms = cmp::min(max_delay_ms, delay_ms * 2);
                                member_delay_ms.insert(retry_peer, delay_ms);

                                futures.push(Box::pin({
                                    let method = &method;
                                    let params = &params;
                                    async move {
                                        // Note: we need to sleep inside the retrying future,
                                        // so that `futures` is being polled continuously
                                        sleep(Duration::from_millis(delay_ms)).await;
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
                        QueryStep::FailMembers(failed) => {
                            for (failed_peer, error) in failed {
                                member_errors.insert(failed_peer, error);
                            }
                        }
                        QueryStep::Continue => {}
                        QueryStep::Failure(failed) => {
                            for (failed_peer, error) in failed {
                                member_errors.insert(failed_peer, error);
                            }
                            return Err(FederationError(member_errors));
                        }
                        QueryStep::Success(response) => return Ok(response),
                    }
                }
                None => return Err(FederationError(BTreeMap::new())),
            }
        }
    }

    async fn request_union<Ret>(
        &self,
        method: String,
        params: ApiRequestErased,
    ) -> FederationResult<Vec<Ret>>
    where
        Ret: serde::de::DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        self.request_with_strategy(
            UnionResponses::new(self.all_members().one_honest()),
            method,
            params,
        )
        .await
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
            CurrentConsensus::new(self.all_members().one_honest()),
            method,
            params,
        )
        .await
    }

    async fn request_eventually_consistent<Ret>(
        &self,
        method: String,
        params: ApiRequestErased,
    ) -> FederationResult<Ret>
    where
        Ret: serde::de::DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        self.request_with_strategy(
            EventuallyConsistent::new(self.all_members().one_honest()),
            method,
            params,
        )
        .await
    }
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> FederationApiExt for T where T: IFederationApi {}

dyn_newtype_define! {
    pub DynFederationApi(Arc<IFederationApi>)
}

impl AsRef<dyn IFederationApi + 'static> for DynFederationApi {
    fn as_ref(&self) -> &(dyn IFederationApi + 'static) {
        self.0.as_ref()
    }
}

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

    async fn await_output_outcome<R>(
        &self,
        outpoint: OutPoint,
        timeout: Duration,
        module_decoder: &Decoder,
    ) -> OutputOutcomeResult<R>
    where
        R: OutputOutcome;

    /// Fetch client configuration info only if verified against a federation id
    async fn download_client_config(
        &self,
        info: &WsClientConnectInfo,
        module_gens: CommonModuleGenRegistry,
    ) -> FederationResult<ClientConfig>;

    /// Fetches the server consensus hash if enough peers agree on it
    async fn consensus_config_hash(&self) -> FederationResult<sha256::Hash>;
}
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
                .and_then(|output| {


                    let dyn_outcome = output
                        .try_into_inner_known_module_kind(module_decoder)
                        .map_err(|e| OutputOutcomeError::ResponseDeserialization(e.into()))?;

                    let source_instance = dyn_outcome.module_instance_id();
                    dyn_outcome.as_any().downcast_ref().cloned().ok_or_else(|| {
                        let target_type = std::any::type_name::<R>();
                        OutputOutcomeError::ResponseDeserialization(anyhow!("Could not downcast output outcome with instance id {source_instance} to {target_type}"))
                    })
                })
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> GlobalFederationApi for T
where
    T: IFederationApi + MaybeSend + MaybeSync + 'static,
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
                result: MemberResult<SerdeEpochHistory>,
            ) -> QueryStep<SignedEpochOutcome> {
                let response = result.and_then(|hist| {
                    hist.try_into_inner(&self.decoders)
                        .map_err(|e| MemberError::Rpc(jsonrpsee_core::Error::Custom(e.to_string())))
                });
                match self.strategy.process(peer, response) {
                    QueryStep::RetryMembers(r) => QueryStep::RetryMembers(r),
                    QueryStep::FailMembers(failed) => QueryStep::FailMembers(failed),
                    QueryStep::Continue => QueryStep::Continue,
                    QueryStep::Success(res) => QueryStep::Success(res),
                    QueryStep::Failure(failed) => QueryStep::Failure(failed),
                }
            }
        }

        let qs = ValidHistoryWrapper {
            decoders,
            strategy: VerifiableResponse::new(
                self.all_members().one_honest(),
                true,
                move |epoch: &SignedEpochOutcome| epoch.verify_sig(&epoch_pk).is_ok(),
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
        self.request_eventually_consistent(
            "fetch_epoch_count".to_owned(),
            ApiRequestErased::default(),
        )
        .await
    }

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
            let tx_outcome = self.await_tx_outcome(&outpoint.txid).await?;
            map_tx_outcome_outpoint(tx_outcome, outpoint, module_decoder)
        })
        .await
        .map_err(|_| OutputOutcomeError::Timeout(timeout))?
    }

    async fn download_client_config(
        &self,
        info: &WsClientConnectInfo,
        module_gens: CommonModuleGenRegistry,
    ) -> FederationResult<ClientConfig> {
        let id = info.id.clone();
        let qs = VerifiableResponse::new(
            self.all_members().total(),
            false,
            move |config: &ConfigResponse| {
                let hash = config.client.consensus_hash(&module_gens).expect("Hashes");

                if let Some(sig) = &config.client_hash_signature {
                    id.0.verify(sig, hash)
                } else {
                    false
                }
            },
        );

        self.request_with_strategy(qs, "config".to_owned(), ApiRequestErased::new(info.clone()))
            .await
            .map(|cfg: ConfigResponse| cfg.client)
    }

    async fn consensus_config_hash(&self) -> FederationResult<sha256::Hash> {
        self.request_current_consensus("config_hash".to_owned(), ApiRequestErased::default())
            .await
    }
}

/// Mint API client that will try to run queries against all `members` expecting
/// equal results from at least `min_eq_results` of them. Members that return
/// differing results are returned as a member faults list.
#[derive(Debug)]
pub struct WsFederationApi<C = WsClient> {
    peers: BTreeSet<PeerId>,
    members: Vec<FederationMember<C>>,
}

#[derive(Debug)]
struct FederationMember<C> {
    url: Url,
    peer_id: PeerId,
    client: RwLock<Option<C>>,
}

/// Information required for client to construct [`WsFederationApi`] instance
///
/// Can be used to download the configs and bootstrap a client
#[derive(Clone, Debug, Eq, PartialEq, Encodable)]
pub struct WsClientConnectInfo {
    /// Url to reach an API that we can download configs from
    pub url: Url,
    /// Config download token (might only be used a certain number of times)
    pub download_token: ClientConfigDownloadToken,
    /// Authentication id for the federation
    pub id: FederationId,
}

/// Size of a download token
const CONFIG_DOWNLOAD_TOKEN_BYTES: usize = 12;

/// Allows a client to download the config
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ClientConfigDownloadToken(pub [u8; CONFIG_DOWNLOAD_TOKEN_BYTES]);

/// We can represent client connect info as a bech32 string for compactness and
/// error-checking
///
/// Human readable part (HRP) includes the version
/// ```txt
/// [ hrp (4 bytes) ] [ id (48 bytes) ] ([ url len (2 bytes) ] [ url bytes (url len bytes) ])+
/// ```
const BECH32_HRP: &str = "fed1";

impl FromStr for WsClientConnectInfo {
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

/// Parses the connect info from a bech32 string
impl Display for WsClientConnectInfo {
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

impl Serialize for WsClientConnectInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        String::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for WsClientConnectInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = Cow::<str>::deserialize(deserializer)?;
        Self::from_str(&string).map_err(serde::de::Error::custom)
    }
}

#[apply(async_trait_maybe_send!)]
impl<C: JsonRpcClient + Debug + MaybeSend + MaybeSync> IFederationApi for WsFederationApi<C> {
    fn all_members(&self) -> &BTreeSet<PeerId> {
        &self.peers
    }

    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &[Value],
    ) -> JsonRpcResult<Value> {
        let member = self
            .members
            .iter()
            .find(|m| m.peer_id == peer_id)
            .ok_or_else(|| JsonRpcError::Custom(format!("Invalid peer_id: {peer_id}")))?;

        member.request(method, params).await
    }
}

#[apply(async_trait_maybe_send!)]
pub trait JsonRpcClient: ClientT + Sized {
    async fn connect(url: &Url) -> result::Result<Self, JsonRpcError>;
    fn is_connected(&self) -> bool;
}

#[apply(async_trait_maybe_send!)]
impl JsonRpcClient for WsClient {
    async fn connect(url: &Url) -> result::Result<Self, JsonRpcError> {
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
    pub fn new(members: Vec<(PeerId, Url)>) -> Self {
        Self::new_with_client(members)
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

    /// Creates a new API client from a connect info, assumes they are in peer
    /// id order
    pub fn from_connect_info(info: &[WsClientConnectInfo]) -> Self {
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
        self.members.iter().map(|member| member.peer_id).collect()
    }

    /// Creates a new API client
    pub fn new_with_client(members: Vec<(PeerId, Url)>) -> Self {
        WsFederationApi {
            peers: members.iter().map(|m| m.0).collect(),
            members: members
                .into_iter()
                .map(|(peer_id, url)| {
                    assert!(
                        url.port_or_known_default().is_some(),
                        "API client requires a port"
                    );
                    assert!(url.host().is_some(), "API client requires a target host");

                    FederationMember {
                        peer_id,
                        url,
                        client: RwLock::new(None),
                    }
                })
                .collect(),
        }
    }
}

#[derive(Debug)]
pub struct PeerResponse<R> {
    pub peer: PeerId,
    pub result: JsonRpcResult<R>,
}

impl<C: JsonRpcClient> FederationMember<C> {
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
                        error!(
                            target: LOG_NET_API,
                            %err, "unable to connect to server");
                        return Err(err)?;
                    }
                }
            }
        })
    }
}

/// `jsonrpsee` converts the `Url` to a `&str` internally and then parses it as
/// an `Uri`. Unfortunately `Url` swallows ports that it considers default ports
/// (e.g. 80 and 443 for HTTP(S)) which makes the `Uri` parsing fail in these
/// cases. This function works around this limitation in a limited way (not
/// fully standard compliant, but work for our use case).
///
/// See <https://github.com/paritytech/jsonrpsee/issues/554#issue-1048646896>
fn url_to_string_with_default_port(url: &Url) -> String {
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

        async fn connect(_url: &Url) -> Result<Self> {
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

    fn federation_member<C: SimpleClient + MaybeSend + MaybeSync>() -> FederationMember<Client<C>> {
        FederationMember {
            url: Url::from_str("http://127.0.0.1").expect("Could not parse"),
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

        let fed = federation_member::<Client>();
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
                tokio::time::sleep(Duration::from_millis(100)).await;
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

        let fed = federation_member::<Client>();

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
    fn converts_connect_string() {
        let connect = WsClientConnectInfo {
            url: "ws://test1".parse().unwrap(),
            id: FederationId::dummy(),
            download_token: ClientConfigDownloadToken(OsRng::default().gen()),
        };

        let bech32 = connect.to_string();
        let connect_parsed = WsClientConnectInfo::from_str(&bech32).expect("parses");
        assert_eq!(connect, connect_parsed);

        let json = serde_json::to_string(&connect).unwrap();
        let connect_as_string: String = serde_json::from_str(&json).unwrap();
        assert_eq!(connect_as_string, bech32);
        let connect_parsed_json: WsClientConnectInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(connect_parsed_json, connect_parsed);
    }
}
