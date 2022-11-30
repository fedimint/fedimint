use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::{Address, Amount};
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_api::backup::SignedBackupRequest;
use fedimint_api::config::ClientConfig;
use fedimint_api::core::client::ClientModule;
use fedimint_api::encoding::ModuleRegistry;
use fedimint_api::task::{sleep, RwLock, RwLockWriteGuard};
use fedimint_api::{dyn_newtype_define, NumPeers, OutPoint, PeerId, TransactionId};
use fedimint_core::epoch::{EpochHistory, SerdeEpochHistory};
use fedimint_core::modules::ln::contracts::incoming::IncomingContractOffer;
use fedimint_core::modules::ln::contracts::ContractId;
use fedimint_core::modules::ln::{ContractAccount, LightningGateway};
use fedimint_core::modules::wallet::PegOutFees;
use fedimint_core::outcome::legacy::{OutputOutcome, TryIntoOutcome};
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::transaction::legacy::Transaction as LegacyTransaction;
use fedimint_core::transaction::SerdeTransaction;
use fedimint_core::CoreError;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_core::client::CertificateStore;
use jsonrpsee_core::client::ClientT;
use jsonrpsee_core::Error as JsonRpcError;
use jsonrpsee_types::error::CallError as RpcCallError;
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use threshold_crypto::PublicKey;
use tracing::{debug, error, instrument, trace, warn};
use url::Url;

use crate::module_decode_stubs;
use crate::query::{
    CurrentConsensus, EventuallyConsistent, QueryStep, QueryStrategy, Retry404, TrustAllPeers,
    UnionResponses, ValidHistory,
};

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait IFederationApi: Debug + Send + Sync {
    /// Fetch the outcome of an entire transaction
    async fn fetch_tx_outcome(&self, tx: TransactionId) -> Result<TransactionStatus>;

    /// Submit a transaction to all federation members
    async fn submit_transaction(&self, tx: LegacyTransaction) -> Result<TransactionId>;

    async fn fetch_epoch_history(&self, epoch: u64, epoch_pk: PublicKey) -> Result<EpochHistory>;

    async fn fetch_last_epoch(&self) -> Result<u64>;

    // TODO: more generic module API extensibility
    /// Fetch ln contract state
    async fn fetch_contract(&self, contract: ContractId) -> Result<ContractAccount>;

    /// Fetch preimage offer for incoming lightning payments
    async fn fetch_offer(&self, payment_hash: Sha256Hash) -> Result<IncomingContractOffer>;

    // TODO: find a better abstraction for all our API endpoints that allows different strategies and timeouts
    /// Checks if there exists an offer for a payment hash
    async fn offer_exists(&self, payment_hash: Sha256Hash) -> Result<bool>;

    /// Fetch the current consensus block height (trailing actual block height)
    async fn fetch_consensus_block_height(&self) -> Result<u64>;

    /// Fetch the expected peg-out fees given a peg-out tx
    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: &Amount,
    ) -> Result<Option<PegOutFees>>;

    /// Fetch available lightning gateways (assumes gateways register with all peers)
    async fn fetch_gateways(&self) -> Result<Vec<LightningGateway>>;

    /// Register a gateway with the federation
    async fn register_gateway(&self, gateway: LightningGateway) -> Result<()>;

    /// Upload ecash (encrypted) backup for mint to safekeep
    async fn upload_ecash_backup(&self, request: &SignedBackupRequest) -> Result<()>;

    /// Download ecash (encrypted) backup from mint to safekeep
    async fn download_ecash_backup(&self, id: &secp256k1::XOnlyPublicKey) -> Result<Vec<u8>>;
}

dyn_newtype_define! {
    pub FederationApi(Arc<IFederationApi>)
}

impl FederationApi {
    pub async fn fetch_output_outcome<T>(&self, out_point: OutPoint) -> Result<T>
    where
        T: TryIntoOutcome + Send,
    {
        match self.fetch_tx_outcome(out_point.txid).await? {
            TransactionStatus::Rejected(e) => Err(ApiError::TransactionRejected(e)),
            TransactionStatus::Accepted { outputs, .. } => {
                let outputs_len = outputs.len();
                outputs
                    .into_iter()
                    .nth(out_point.out_idx as usize) // avoid clone as would be necessary with .get(…)
                    .ok_or(ApiError::OutPointOutOfRange(
                        outputs_len,
                        out_point.out_idx as usize,
                    ))
                    .and_then(|output| {
                        let legacy_oo: OutputOutcome =
                            output.try_into_inner(&module_decode_stubs())?.into();

                        legacy_oo.try_into_variant().map_err(ApiError::CoreError)
                    })
            }
        }
    }

    // TODO should become part of the API
    pub async fn await_output_outcome<T: TryIntoOutcome + Send>(
        &self,
        outpoint: OutPoint,
        timeout: Duration,
    ) -> Result<T> {
        let poll = || async {
            let interval = Duration::from_secs(1);
            loop {
                match self.fetch_output_outcome(outpoint).await {
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
            .map_err(|_| ApiError::Timeout)?
    }
}

/// Mint API client that will try to run queries against all `members` expecting equal
/// results from at least `min_eq_results` of them. Members that return differing results are
/// returned as a member faults list.
#[derive(Debug)]
pub struct WsFederationApi<C = WsClient> {
    members: Vec<FederationMember<C>>,
    module_registry: ModuleRegistry<fedimint_api::core::client::ClientModule>,
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

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Rpc error: {0}")]
    RpcError(#[from] JsonRpcError),
    #[error("Decode error: {0}")]
    DecodeError(#[from] fedimint_api::encoding::DecodeError),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Error retrieving the transaction: {0}")]
    TransactionError(String),
    #[error("The transaction was rejected by consensus processing: {0}")]
    TransactionRejected(String),
    #[error("Out point out of range, transaction got {0} outputs, requested element {1}")]
    OutPointOutOfRange(usize, usize),
    #[error("Core error: {0}")]
    CoreError(#[from] CoreError),
    #[error("Timeout error awaiting outcome")]
    Timeout,
    #[error("Unable to determine a consistent API result from peers")]
    NoResult,
}

impl ApiError {
    /// Returns `true` if queried outpoint isn't ready yet but may become ready later
    pub fn is_retryable(&self) -> bool {
        match self {
            ApiError::RpcError(JsonRpcError::Call(RpcCallError::Custom(e))) => e.code() == 404,
            ApiError::CoreError(e) => e.is_retryable(),
            _ => false,
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<C: JsonRpcClient + Debug + Send + Sync> IFederationApi for WsFederationApi<C> {
    /// Fetch the outcome of an entire transaction
    async fn fetch_tx_outcome(&self, tx: TransactionId) -> Result<TransactionStatus> {
        self.request(
            "/fetch_transaction",
            tx,
            Retry404::new(self.peers().one_honest()),
        )
        .await
    }

    /// Submit a transaction to all federation members
    async fn submit_transaction(&self, tx: LegacyTransaction) -> Result<TransactionId> {
        // TODO: check the id is correct
        self.request(
            "/transaction",
            SerdeTransaction::from(&tx.into_type_erased()),
            CurrentConsensus::new(self.peers().one_honest()),
        )
        .await
    }

    async fn fetch_epoch_history(&self, epoch: u64, epoch_pk: PublicKey) -> Result<EpochHistory> {
        struct ValidHistoryWrapper<'a> {
            modules: &'a ModuleRegistry<ClientModule>,
            strategy: ValidHistory,
        }

        impl<'a> QueryStrategy<SerdeEpochHistory> for ValidHistoryWrapper<'a> {
            fn process(
                &mut self,
                response: FedResponse<SerdeEpochHistory>,
            ) -> QueryStep<SerdeEpochHistory> {
                let response = FedResponse {
                    peer: response.peer,
                    result: response.result.and_then(|hist| {
                        hist.try_into_inner(self.modules)
                            .map_err(|e| jsonrpsee_core::Error::Custom(e.to_string()))
                    }),
                };
                match self.strategy.process(response) {
                    QueryStep::Finished(res) => QueryStep::Finished(res.map(|val| (&val).into())),
                    QueryStep::Retry(r) => QueryStep::Retry(r),
                    QueryStep::Continue => QueryStep::Continue,
                }
            }
        }

        let qs = ValidHistoryWrapper {
            modules: &self.module_registry,
            strategy: ValidHistory::new(epoch_pk, self.peers().one_honest()),
        };

        Ok(self
            .request::<_, SerdeEpochHistory>("/fetch_epoch_history", epoch, qs)
            .await?
            .try_into_inner(&self.module_registry)?)
    }

    async fn fetch_last_epoch(&self) -> Result<u64> {
        self.request(
            "/epoch",
            (),
            EventuallyConsistent::new(self.peers().one_honest()),
        )
        .await
    }

    async fn fetch_contract(&self, contract: ContractId) -> Result<ContractAccount> {
        self.request(
            "/ln/account",
            contract,
            Retry404::new(self.peers().one_honest()),
        )
        .await
    }

    async fn fetch_consensus_block_height(&self) -> Result<u64> {
        self.request(
            "/wallet/block_height",
            (),
            EventuallyConsistent::new(self.peers().one_honest()),
        )
        .await
    }

    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: &Amount,
    ) -> Result<Option<PegOutFees>> {
        self.request(
            "/wallet/peg_out_fees",
            (address, amount.to_sat()),
            EventuallyConsistent::new(self.peers().one_honest()),
        )
        .await
    }

    async fn fetch_offer(&self, payment_hash: Sha256Hash) -> Result<IncomingContractOffer> {
        self.request(
            "/ln/offer",
            payment_hash,
            Retry404::new(self.peers().one_honest()),
        )
        .await
    }

    async fn fetch_gateways(&self) -> Result<Vec<LightningGateway>> {
        self.request(
            "/ln/list_gateways",
            (),
            UnionResponses::new(self.peers().one_honest()),
        )
        .await
    }

    async fn register_gateway(&self, gateway: LightningGateway) -> Result<()> {
        self.request(
            "/ln/register_gateway",
            gateway,
            CurrentConsensus::new(self.peers().threshold()),
        )
        .await
    }

    async fn offer_exists(&self, payment_hash: Sha256Hash) -> Result<bool> {
        let res: Result<IncomingContractOffer> = self
            .request(
                "/ln/offer",
                payment_hash,
                CurrentConsensus::new(self.peers().one_honest()),
            )
            .await;

        match res {
            Ok(_) => Ok(true),
            Err(e) if e.is_retryable() => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn upload_ecash_backup(&self, request: &SignedBackupRequest) -> Result<()> {
        self.request(
            "/mint/backup",
            request,
            CurrentConsensus::new(self.peers().threshold()),
        )
        .await
    }

    async fn download_ecash_backup(&self, id: &secp256k1::XOnlyPublicKey) -> Result<Vec<u8>> {
        let hex_str: String = self
            .request(
                "/mint/recover",
                id,
                // TODO: do we need a different strategy for this?
                TrustAllPeers,
            )
            .await?;

        Ok(hex::decode(&hex_str).map_err(|e| ApiError::InvalidResponse(e.to_string()))?)
    }
}

#[async_trait]
pub trait JsonRpcClient: ClientT + Sized {
    async fn connect(url: &Url) -> std::result::Result<Self, JsonRpcError>;
    fn is_connected(&self) -> bool;
}

#[async_trait]
impl JsonRpcClient for WsClient {
    async fn connect(url: &Url) -> std::result::Result<Self, JsonRpcError> {
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
            module_registry: module_decode_stubs(),
        }
    }
}

pub struct FedResponse<R> {
    pub peer: PeerId,
    pub result: std::result::Result<R, JsonRpcError>,
}

impl<C: JsonRpcClient> FederationMember<C> {
    #[instrument(fields(peer = %self.peer_id), skip_all)]
    pub async fn request<R>(&self, method: &str, params: &[serde_json::Value]) -> FedResponse<R>
    where
        R: serde::de::DeserializeOwned,
    {
        let rclient = self.client.read().await;
        match &*rclient {
            Some(client) if client.is_connected() => {
                return FedResponse {
                    peer: self.peer_id,
                    result: client.request::<R, _>(method, params).await,
                };
            }
            _ => {}
        };

        debug!("web socket not connected, reconnecting");

        drop(rclient);
        let mut wclient = self.client.write().await;
        let response = match &*wclient {
            Some(client) if client.is_connected() => {
                // other task has already connected it
                let rclient = RwLockWriteGuard::downgrade(wclient);
                rclient
                    .as_ref()
                    .unwrap()
                    .request::<R, _>(method, params)
                    .await
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
                            .request::<R, _>(method, params)
                            .await
                    }
                    Err(err) => {
                        error!(%err, "unable to connect to server");
                        Err(err)
                    }
                }
            }
        };

        FedResponse {
            peer: self.peer_id,
            result: response,
        }
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

impl<C: JsonRpcClient> WsFederationApi<C> {
    pub async fn request<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        param: P,
        mut strategy: impl QueryStrategy<R>,
    ) -> Result<R> {
        let params = [serde_json::to_value(param).expect("encoding error")];
        let mut futures = FuturesUnordered::new();

        for member in &self.members {
            futures.push(member.request(method, &params));
        }

        // Delegates the response handling to the `QueryStrategy` with an exponential back-off
        // with every new set of requests
        let mut delay_ms = 10;
        loop {
            match futures.next().await {
                Some(result) => match strategy.process(result) {
                    QueryStep::Retry(peers) => {
                        for member in &self.members {
                            if peers.contains(&member.peer_id) {
                                futures.push(member.request(method, &params));
                            }
                        }
                        sleep(Duration::from_millis(delay_ms)).await;
                        delay_ms *= 2;
                    }
                    QueryStep::Continue => {}
                    QueryStep::Finished(result) => return result,
                },
                None => return Err(ApiError::NoResult),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        fmt,
        str::FromStr,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Mutex,
        },
    };

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

        fed.request::<()>("", &[]).await.result.unwrap();
        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            1,
            "should connect once after first request"
        );

        fed.request::<()>("", &[]).await.result.unwrap();
        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            1,
            "should not connect again before disconnect"
        );

        // disconnect
        CONNECTED.store(false, Ordering::SeqCst);

        fed.request::<()>("", &[]).await.result.unwrap();
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
            fed.request::<()>("", &[]).await.result.is_err(),
            "connect for client 0 should fail"
        );

        // connect for client 1 should succeed
        fed.request::<()>("", &[]).await.result.unwrap();

        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            2,
            "should connect again after error in first connect"
        );

        // force a new connection by disconnecting client 1
        FAIL.lock().unwrap().insert(1);

        // only connect once even for two concurrent requests
        let (reqa, reqb) = tokio::join!(fed.request::<()>("", &[]), fed.request::<()>("", &[]));
        reqa.result.expect("both request should be successful");
        reqb.result.expect("both request should be successful");

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
        let (reqa, reqb) = tokio::join!(fed.request::<()>("", &[]), fed.request::<()>("", &[]));

        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            5,
            "should connect again if first concurrent request fails",
        );

        assert!(
            reqa.result.is_err() ^ reqb.result.is_err(),
            "exactly one of two request should succeed"
        );
    }
}
