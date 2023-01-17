use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, result};

use async_trait::async_trait;
use bitcoin::Address;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_api::config::ClientConfig;
use fedimint_api::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_api::module::registry::ModuleDecoderRegistry;
use fedimint_api::task::{sleep, RwLock, RwLockWriteGuard};
use fedimint_api::{dyn_newtype_define, NumPeers, OutPoint, PeerId, TransactionId};
use fedimint_core::epoch::{SerdeEpochHistory, SignedEpochOutcome};
use fedimint_core::modules::ln::contracts::incoming::IncomingContractOffer;
use fedimint_core::modules::ln::contracts::ContractId;
use fedimint_core::modules::ln::{ContractAccount, LightningGateway};
use fedimint_core::modules::wallet::PegOutFees;
use fedimint_core::outcome::legacy::TryIntoOutcome;
use fedimint_core::outcome::{self, TransactionStatus};
use fedimint_core::transaction::SerdeTransaction;
use fedimint_core::CoreError;
use fedimint_mint::db::ECashUserBackupSnapshot;
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_core::client::CertificateStore;
use jsonrpsee_core::client::ClientT;
use jsonrpsee_core::Error as JsonRpcError;
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use threshold_crypto::PublicKey;
use tracing::{debug, error, instrument, trace, warn};
use url::Url;

use crate::query::{
    CurrentConsensus, EventuallyConsistent, QueryStep, QueryStrategy, Retry404, UnionResponses,
    UnionResponsesSingle, ValidHistory,
};
use crate::LegacyTransaction;

type JsonValue = serde_json::Value;

pub type MemberResult<T> = result::Result<T, MemberError>;

pub type JsonRpcResult<T> = result::Result<T, jsonrpsee_core::Error>;
pub type FederationResult<T> = result::Result<T, FederationError>;

pub mod fake;

/// An API request error when calling a single federation member
#[derive(Debug, Error)]
pub enum MemberError {
    #[error("Response deserialization error: {0}")]
    ResponseDeserialization(anyhow::Error),
    #[error("Invalid peer id: {peer_id}")]
    InvalidPeerId { peer_id: PeerId },
    #[error("Rpc error: {0}")]
    Rpc(#[from] JsonRpcError),
}

impl MemberError {
    pub fn is_retryable(&self) -> bool {
        match self {
            MemberError::ResponseDeserialization(_) => false,
            MemberError::InvalidPeerId { peer_id: _ } => false,
            MemberError::Rpc(rpc_e) => match rpc_e {
                JsonRpcError::Transport(_) => true,
                JsonRpcError::Internal(_) => true,
                JsonRpcError::Call(jsonrpsee_types::error::CallError::Custom(e)) => e.code() == 404,
                _ => false,
            },
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
            f.write_fmt(format_args!("{} => {})", peer, e))?;
            if i == self.0.len() - 1 {
                f.write_str(", ")?;
            }
        }
        f.write_str(")")?;
        Ok(())
    }
}

impl FederationError {
    fn is_retryable(&self) -> bool {
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
    Core(#[from] CoreError),
    #[error("Transaction rejected: {0}")]
    Rejected(String),
    #[error("Invalid output index {out_idx}, larger than {outputs_num} in the transaction")]
    InvalidVout { out_idx: u64, outputs_num: usize },
    #[error("Timeout reached after waiting {}s", .0.as_secs())]
    Timeout(Duration),
}

impl OutputOutcomeError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Federation(fed) => fed.is_retryable(),
            Self::Core(CoreError::PendingPreimage) => true,
            _ => false,
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait IFederationApi: Debug {
    /// List of all federation members for the purpose of iterating each member in the federation.
    ///
    /// The underlying implementation is resonsible for knowing how many
    /// and `PeerId`s of each. The caller of this interface most probably
    /// have some idea as well, but passing this set accross every
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

/// Build a `Vec<json::Value>` that [`IFederationApi::request_raw`] expects when no arguments are passed to the API call
///
/// Notably the caling convention of fedimintd api is a bit weird ATM, so by using this function you'll make it easier
/// to change it in the future.
pub fn erased_no_param() -> Vec<JsonValue> {
    vec![JsonValue::Null]
}

/// Build a `Vec<json::Value>` that [`IFederationApi::request_raw`] expects when one argument are passed to the API call
///
/// Notably the caling convention of fedimintd api is a bit weird ATM, so by using this function you'll make it easier
/// to change it in the future.
pub fn erased_single_param<Params>(param: &Params) -> Vec<JsonValue>
where
    Params: Serialize,
{
    let params_raw = serde_json::to_value(param)
        .expect("parameter serialization error - this should not happen");

    vec![params_raw]
}

/// Build a `Vec<json::Value>` that [`IFederationApi::request_raw`] expects when multiple argument are passed to the API call
///
/// Use a tuple as `params`.
///
/// Notably the caling convention of fedimintd api is a bit weird ATM, so by using this function you'll make it easier
/// to change it in the future.
pub fn erased_multi_param<Params>(param: &Params) -> Vec<JsonValue>
where
    Params: Serialize,
{
    let params_raw = serde_json::to_value(param)
        .expect("parameter serialization error - this should not happen");

    vec![params_raw]
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
/// An extension trait allowing to making federation-wide API call on top [`IFederationApi`].
pub trait FederationApiExt: IFederationApi {
    /// Make an aggregate request to federation, using `strategy` to logically merge the responses.
    async fn request_with_strategy<MemberRet: serde::de::DeserializeOwned, FedRet: Debug>(
        &self,
        mut strategy: impl QueryStrategy<MemberRet, FedRet> + Send,
        method: String,
        params: Vec<Value>,
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
                    result: self.request_raw(*peer_id, &method, &params).await,
                }
            }));
        }

        let mut member_delay_ms = BTreeMap::new();
        let mut member_errors = BTreeMap::new();

        // Delegates the response handling to the `QueryStrategy` with an exponential back-off
        // with every new set of requests
        let max_delay_ms = 1000;
        loop {
            let response = futures.next().await;
            trace!(?response, method, ?params, "Received member response");
            match response {
                Some(PeerResponse { peer, result }) => {
                    let result: MemberResult<MemberRet> =
                        result.map_err(MemberError::Rpc).and_then(|o| {
                            serde_json::from_value::<MemberRet>(o)
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
                                        // so that `futures` is being polled continously
                                        sleep(Duration::from_millis(delay_ms)).await;
                                        PeerResponse {
                                            peer: retry_peer,
                                            result: self
                                                .request_raw(retry_peer, method, params)
                                                .await,
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
                            return Err(FederationError(BTreeMap::new()));
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
        params: Vec<Value>,
    ) -> FederationResult<Vec<Ret>>
    where
        Ret: serde::de::DeserializeOwned + Eq + Debug + Clone + Send,
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
        params: Vec<Value>,
    ) -> FederationResult<Ret>
    where
        Ret: serde::de::DeserializeOwned + Eq + Debug + Clone + Send,
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
        params: Vec<Value>,
    ) -> FederationResult<Ret>
    where
        Ret: serde::de::DeserializeOwned + Eq + Debug + Clone + Send,
    {
        self.request_with_strategy(
            EventuallyConsistent::new(self.all_members().one_honest()),
            method,
            params,
        )
        .await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<T: ?Sized> FederationApiExt for T where T: IFederationApi {}

dyn_newtype_define! {
    pub DynFederationApi(Arc<IFederationApi>)
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait GlobalFederationApi {
    async fn get_client_config(&self) -> FederationResult<ClientConfig>;

    async fn submit_transaction(&self, tx: LegacyTransaction) -> FederationResult<TransactionId>;
    async fn fetch_tx_outcome(&self, txid: &TransactionId) -> FederationResult<TransactionStatus>;

    async fn fetch_epoch_history(
        &self,
        epoch: u64,
        epoch_pk: PublicKey,
        decoders: &ModuleDecoderRegistry,
    ) -> FederationResult<SignedEpochOutcome>;

    async fn fetch_last_epoch(&self) -> FederationResult<u64>;

    async fn fetch_output_outcome<R>(
        &self,
        out_point: OutPoint,
        decoders: &ModuleDecoderRegistry,
    ) -> OutputOutcomeResult<R>
    where
        R: TryIntoOutcome + Send;

    async fn await_output_outcome<R: TryIntoOutcome + Send>(
        &self,
        outpoint: OutPoint,
        timeout: Duration,
        decoders: &ModuleDecoderRegistry,
    ) -> OutputOutcomeResult<R>;
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<T: ?Sized> GlobalFederationApi for T
where
    T: IFederationApi + Send + Sync + 'static,
{
    async fn get_client_config(&self) -> FederationResult<ClientConfig> {
        self.request_current_consensus("/config".to_owned(), erased_no_param())
            .await
    }

    /// Submit a transaction for inclusion
    async fn submit_transaction(&self, tx: LegacyTransaction) -> FederationResult<TransactionId> {
        self.request_current_consensus(
            "/transaction".to_owned(),
            erased_single_param(&SerdeTransaction::from(&tx.into_type_erased())),
        )
        .await
    }

    /// Fetch the outcome of an entire transaction
    async fn fetch_tx_outcome(&self, tx: &TransactionId) -> FederationResult<TransactionStatus> {
        self.request_with_strategy(
            Retry404::new(self.all_members().one_honest()),
            "/fetch_transaction".to_owned(),
            erased_single_param(&tx),
        )
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
            strategy: ValidHistory,
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
            strategy: ValidHistory::new(epoch_pk, self.all_members().one_honest()),
        };

        self.request_with_strategy::<SerdeEpochHistory, _>(
            qs,
            "/fetch_epoch_history".to_owned(),
            erased_single_param(&epoch),
        )
        .await
    }

    async fn fetch_last_epoch(&self) -> FederationResult<u64> {
        self.request_eventually_consistent("/epoch".to_owned(), erased_no_param())
            .await
    }

    async fn fetch_output_outcome<R>(
        &self,
        out_point: OutPoint,
        decoders: &ModuleDecoderRegistry,
    ) -> OutputOutcomeResult<R>
    where
        R: TryIntoOutcome + Send,
    {
        match self.fetch_tx_outcome(&out_point.txid).await? {
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
                        let legacy_oo: outcome::legacy::OutputOutcome = output
                            .try_into_inner(decoders)
                            .map_err(|e| OutputOutcomeError::ResponseDeserialization(e.into()))?
                            .into();
                        legacy_oo
                            .try_into_variant()
                            .map_err(OutputOutcomeError::Core)
                    })
            }
        }
    }

    // TODO should become part of the API
    async fn await_output_outcome<R: TryIntoOutcome + Send>(
        &self,
        outpoint: OutPoint,
        timeout: Duration,
        decoders: &ModuleDecoderRegistry,
    ) -> OutputOutcomeResult<R> {
        let poll = || async {
            let interval = Duration::from_secs(1);
            loop {
                match self.fetch_output_outcome(outpoint, decoders).await {
                    Ok(t) => return Ok(t),
                    Err(e) if e.is_retryable() => {
                        trace!("Federation api returned retryable error: {:?}", e);
                        fedimint_api::task::sleep(interval).await
                    }
                    Err(e) => {
                        warn!("Federation api returned error: {:?}", e);
                        return Err(e);
                    }
                }
            }
        };
        fedimint_api::task::timeout(timeout, poll())
            .await
            .map_err(|_| OutputOutcomeError::Timeout(timeout))?
    }
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait LnFederationApi {
    async fn fetch_contract(&self, contract: ContractId) -> FederationResult<ContractAccount>;
    async fn fetch_offer(
        &self,
        payment_hash: Sha256Hash,
    ) -> FederationResult<IncomingContractOffer>;
    async fn fetch_gateways(&self) -> FederationResult<Vec<LightningGateway>>;
    async fn register_gateway(&self, gateway: &LightningGateway) -> FederationResult<()>;
    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool>;
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<T: ?Sized> LnFederationApi for T
where
    T: IFederationApi + Send + Sync + 'static,
{
    async fn fetch_contract(&self, contract: ContractId) -> FederationResult<ContractAccount> {
        self.request_with_strategy(
            Retry404::new(self.all_members().one_honest()),
            format!("/module/{}/account", LEGACY_HARDCODED_INSTANCE_ID_LN),
            erased_single_param(&contract),
        )
        .await
    }
    async fn fetch_offer(
        &self,
        payment_hash: Sha256Hash,
    ) -> FederationResult<IncomingContractOffer> {
        self.request_with_strategy(
            Retry404::new(self.all_members().one_honest()),
            format!("/module/{}/offer", LEGACY_HARDCODED_INSTANCE_ID_LN),
            erased_single_param(&payment_hash),
        )
        .await
    }

    async fn fetch_gateways(&self) -> FederationResult<Vec<LightningGateway>> {
        self.request_union(
            format!("/module/{}/list_gateways", LEGACY_HARDCODED_INSTANCE_ID_LN),
            erased_no_param(),
        )
        .await
    }

    async fn register_gateway(&self, gateway: &LightningGateway) -> FederationResult<()> {
        self.request_current_consensus(
            format!(
                "/module/{}/register_gateway",
                LEGACY_HARDCODED_INSTANCE_ID_LN
            ),
            erased_single_param(gateway),
        )
        .await
    }

    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool> {
        match self.fetch_offer(payment_hash).await {
            Ok(_) => Ok(true),
            Err(e) if e.is_retryable() => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait MintFederationApi {
    async fn upload_ecash_backup(
        &self,
        request: &fedimint_mint::SignedBackupRequest,
    ) -> FederationResult<()>;
    async fn download_ecash_backup(
        &self,
        id: &secp256k1::XOnlyPublicKey,
    ) -> FederationResult<Vec<ECashUserBackupSnapshot>>;
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<T: ?Sized> MintFederationApi for T
where
    T: IFederationApi + Send + Sync + 'static,
{
    async fn upload_ecash_backup(
        &self,
        request: &fedimint_mint::SignedBackupRequest,
    ) -> FederationResult<()> {
        self.request_current_consensus(
            format!("/module/{}/backup", LEGACY_HARDCODED_INSTANCE_ID_MINT),
            erased_single_param(request),
        )
        .await
    }
    async fn download_ecash_backup(
        &self,
        id: &secp256k1::XOnlyPublicKey,
    ) -> FederationResult<Vec<ECashUserBackupSnapshot>> {
        Ok(self
            .request_with_strategy(
                UnionResponsesSingle::<Option<ECashUserBackupSnapshot>>::new(
                    self.all_members().one_honest(),
                ),
                format!("/module/{}/recover", LEGACY_HARDCODED_INSTANCE_ID_MINT),
                erased_single_param(id),
            )
            .await?
            .into_iter()
            .flatten()
            .collect())
    }
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait WalletFederationApi {
    async fn fetch_consensus_block_height(&self) -> FederationResult<u64>;
    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>>;
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<T: ?Sized> WalletFederationApi for T
where
    T: IFederationApi + Send + Sync + 'static,
{
    async fn fetch_consensus_block_height(&self) -> FederationResult<u64> {
        self.request_with_strategy(
            EventuallyConsistent::new(self.all_members().one_honest()),
            format!(
                "/module/{}/block_height",
                LEGACY_HARDCODED_INSTANCE_ID_WALLET
            ),
            erased_no_param(),
        )
        .await
    }

    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>> {
        self.request_eventually_consistent(
            format!(
                "/module/{}/peg_out_fees",
                LEGACY_HARDCODED_INSTANCE_ID_WALLET
            ),
            erased_multi_param(&(address, amount.to_sat())),
        )
        .await
    }
}

/// Mint API client that will try to run queries against all `members` expecting equal
/// results from at least `min_eq_results` of them. Members that return differing results are
/// returned as a member faults list.
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
#[derive(Debug, Serialize, Deserialize)]
pub struct WsFederationConnect {
    pub members: Vec<(PeerId, Url)>,
}

impl From<&ClientConfig> for WsFederationConnect {
    fn from(config: &ClientConfig) -> Self {
        let members: Vec<(PeerId, Url)> = config
            .nodes
            .iter()
            .enumerate()
            .map(|(id, node)| {
                let peer_id = PeerId::from(id as u16); // FIXME: potentially wrong, currently works imo
                let url = node.url.clone();
                (peer_id, url)
            })
            .collect();
        WsFederationConnect { members }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<C: JsonRpcClient + Debug + Send + Sync> IFederationApi for WsFederationApi<C> {
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

#[async_trait]
pub trait JsonRpcClient: ClientT + Sized {
    async fn connect(url: &Url) -> result::Result<Self, JsonRpcError>;
    fn is_connected(&self) -> bool;
}

#[async_trait]
impl JsonRpcClient for WsClient {
    async fn connect(url: &Url) -> result::Result<Self, JsonRpcError> {
        #[cfg(not(target_family = "wasm"))]
        return WsClientBuilder::default()
            .certificate_store(CertificateStore::WebPki)
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

    pub fn from_config(config: &ClientConfig) -> Self {
        Self::new(
            config
                .nodes
                .iter()
                .enumerate()
                .map(|(id, node)| {
                    let peer_id = PeerId::from(id as u16); // FIXME: potentially wrong, currently works imo
                    let url = node.url.clone();
                    (peer_id, url)
                })
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
    #[instrument(fields(peer = %self.peer_id), skip_all)]
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
                        error!(%err, "unable to connect to server");
                        return Err(err)?;
                    }
                }
            }
        })
    }
}

/// `jsonrpsee` converts the `Url` to a `&str` internally and then parses it as an `Uri`.
/// Unfortunately `Url` swallows ports that it considers default ports (e.g. 80 and 443 for HTTP(S))
/// which makes the `Uri` parsing fail in these cases. This function works around this limitation in
/// a limited way (not fully standard compliant, but work for our use case).
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
    use serde::de::DeserializeOwned;

    use super::*;

    type Result<T = ()> = std::result::Result<T, JsonRpcError>;

    #[async_trait]
    trait SimpleClient: Sized {
        async fn connect() -> Result<Self>;
        fn is_connected(&self) -> bool {
            true
        }
        // reply with json
        async fn request(&self, method: &str) -> Result<String>;
    }

    struct Client<C: SimpleClient>(C);

    #[async_trait]
    impl<C: SimpleClient + Send + Sync> JsonRpcClient for Client<C> {
        fn is_connected(&self) -> bool {
            self.0.is_connected()
        }

        async fn connect(_url: &Url) -> Result<Self> {
            Ok(Self(C::connect().await?))
        }
    }

    #[async_trait]
    impl<C: SimpleClient + Send + Sync> ClientT for Client<C> {
        async fn request<R, P>(&self, method: &str, _params: P) -> Result<R>
        where
            R: jsonrpsee_core::DeserializeOwned,
            P: ToRpcParams + Send,
        {
            let json = self.0.request(method).await?;
            Ok(serde_json::from_str(&json).unwrap())
        }

        async fn notification<P>(&self, _method: &str, _params: P) -> Result<()>
        where
            P: ToRpcParams + Send,
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

    fn federation_member<C: SimpleClient + Send + Sync>() -> FederationMember<Client<C>> {
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

        #[async_trait]
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

        #[async_trait]
        impl SimpleClient for Client {
            async fn connect() -> Result<Self> {
                tracing::error!("connect");
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
}
