use async_trait::async_trait;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use jsonrpsee_core::client::ClientT;
use jsonrpsee_core::Error as JsonRpcError;
use jsonrpsee_types::error::CallError as RpcCallError;
use minimint_api::task::{RwLock, RwLockWriteGuard};
use minimint_api::{OutPoint, PeerId, TransactionId};
use minimint_core::modules::ln::contracts::incoming::IncomingContractOffer;
use minimint_core::modules::ln::contracts::ContractId;
use minimint_core::modules::ln::ContractAccount;
use minimint_core::outcome::{TransactionStatus, TryIntoOutcome};
use minimint_core::transaction::Transaction;
use minimint_core::CoreError;
use tracing::{error, instrument, warn};

#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};

#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};

use std::time::Duration;
use thiserror::Error;

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait FederationApi: Send + Sync {
    /// Fetch the outcome of an entire transaction
    async fn fetch_tx_outcome(&self, tx: TransactionId) -> Result<TransactionStatus>;

    /// Submit a transaction to all federation members
    async fn submit_transaction(&self, tx: Transaction) -> Result<TransactionId>;

    // TODO: more generic module API extensibility
    /// Fetch ln contract state
    async fn fetch_contract(&self, contract: ContractId) -> Result<ContractAccount>;

    /// Fetch preimage offer for incoming lightning payments
    async fn fetch_offer(&self, payment_hash: Sha256Hash) -> Result<IncomingContractOffer>;

    /// Fetch the current consensus block height (trailing actual block height)
    async fn fetch_consensus_block_height(&self) -> Result<u64>;
}

impl<'a> dyn FederationApi + 'a {
    pub async fn fetch_output_outcome<T>(&self, out_point: OutPoint) -> Result<T>
    where
        T: TryIntoOutcome + Send,
    {
        match self.fetch_tx_outcome(out_point.txid).await? {
            TransactionStatus::Error(e) => Err(ApiError::TransactionError(e)),
            TransactionStatus::Accepted { outputs, .. } => {
                let outputs_len = outputs.len();
                outputs
                    .into_iter()
                    .nth(out_point.out_idx as usize) // avoid clone as would be necessary with .get(…)
                    .ok_or(ApiError::OutPointOutOfRange(
                        outputs_len,
                        out_point.out_idx as usize,
                    ))
                    .and_then(|output| output.try_into_variant().map_err(ApiError::CoreError))
            }
        }
    }

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
                    Err(e) if e.is_retryable() => minimint_api::task::sleep(interval).await,
                    Err(e) => return Err(e),
                }
            }
        };
        minimint_api::task::timeout(timeout, poll())
            .await
            .map_err(|_| ApiError::Timeout)?
    }

    pub async fn await_offer(
        &self,
        payment_hash: Sha256Hash,
        timeout: Duration,
    ) -> Result<IncomingContractOffer> {
        let poll = || async {
            let interval = Duration::from_millis(100);
            loop {
                match self.fetch_offer(payment_hash).await {
                    Ok(t) => return Ok(t),
                    Err(e) if e.is_retryable() => minimint_api::task::sleep(interval).await,
                    Err(e) => return Err(e),
                }
            }
        };
        minimint_api::task::timeout(timeout, poll())
            .await
            .map_err(|_| ApiError::Timeout)?
    }

    pub async fn await_contract(
        &self,
        contract_id: ContractId,
        timeout: Duration,
    ) -> Result<ContractAccount> {
        let poll = || async {
            let interval = Duration::from_millis(100);
            loop {
                match self.fetch_contract(contract_id).await {
                    Ok(t) => return Ok(t),
                    Err(e) if e.is_retryable() => minimint_api::task::sleep(interval).await,
                    Err(e) => return Err(e),
                }
            }
        };
        minimint_api::task::timeout(timeout, poll())
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
    max_evil: usize,
}

#[derive(Debug)]
struct FederationMember<C> {
    url: String,
    peer_id: PeerId,
    client: RwLock<Option<C>>,
}

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Rpc error: {0}")]
    RpcError(#[from] JsonRpcError),
    #[error("Accepted transaction errored on execution: {0}")]
    TransactionError(String),
    #[error("Out point out of range, transaction got {0} outputs, requested element {1}")]
    OutPointOutOfRange(usize, usize),
    #[error("Core error: {0}")]
    CoreError(#[from] CoreError),
    #[error("Timeout error awaiting outcome")]
    Timeout,
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

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<C: JsonRpcClient + Send + Sync> FederationApi for WsFederationApi<C> {
    /// Fetch the outcome of an entire transaction
    async fn fetch_tx_outcome(&self, tx: TransactionId) -> Result<TransactionStatus> {
        self.request("/fetch_transaction", tx).await
    }

    /// Submit a transaction to all federtion members
    async fn submit_transaction(&self, tx: Transaction) -> Result<TransactionId> {
        // TODO: check the id is correct
        self.request("/transaction", tx).await
    }

    async fn fetch_contract(&self, contract: ContractId) -> Result<ContractAccount> {
        self.request("/ln/account", contract).await
    }

    async fn fetch_consensus_block_height(&self) -> Result<u64> {
        self.request("/wallet/block_height", ()).await
    }

    async fn fetch_offer(&self, payment_hash: Sha256Hash) -> Result<IncomingContractOffer> {
        self.request("/ln/offer", payment_hash).await
    }
}

#[async_trait]
pub trait JsonRpcClient: ClientT + Sized {
    async fn connect(url: &str) -> std::result::Result<Self, JsonRpcError>;
    fn is_connected(&self) -> bool;
}

#[async_trait]
impl JsonRpcClient for WsClient {
    async fn connect(url: &str) -> std::result::Result<Self, JsonRpcError> {
        WsClientBuilder::default().build(url).await
    }

    fn is_connected(&self) -> bool {
        self.is_connected()
    }
}

impl WsFederationApi<WsClient> {
    /// Creates a new API client
    pub async fn new(max_evil: usize, members: Vec<(PeerId, String)>) -> Self {
        Self::new_with_client(max_evil, members).await
    }
}

impl<C> WsFederationApi<C> {
    /// Creates a new API client
    pub async fn new_with_client(max_evil: usize, members: Vec<(PeerId, String)>) -> Self {
        WsFederationApi {
            members: members
                .into_iter()
                .map(|(peer_id, url)| FederationMember {
                    peer_id,
                    url,
                    client: RwLock::new(None),
                })
                .collect(),
            max_evil,
        }
    }
}

impl<C: JsonRpcClient> FederationMember<C> {
    #[instrument(fields(peer = %self.peer_id), skip_all, err)]
    pub async fn request<R>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> std::result::Result<R, JsonRpcError>
    where
        R: serde::de::DeserializeOwned,
    {
        let params = Some(jsonrpsee_types::ParamsSer::ArrayRef(params));
        let rclient = self.client.read().await;
        match &*rclient {
            Some(client) if client.is_connected() => {
                return client.request::<R>(method, params).await;
            }
            _ => {}
        };

        warn!("web socket not connected, reconnecting");

        drop(rclient);
        let mut wclient = self.client.write().await;
        match &*wclient {
            Some(client) if client.is_connected() => {
                // other task has already connected it
                let rclient = RwLockWriteGuard::downgrade(wclient);
                rclient.as_ref().unwrap().request::<R>(method, params).await
            }
            _ => {
                // write lock is acquired before creating a new client
                // so only one task will try to create a new client
                match C::connect(&self.url).await {
                    Ok(client) => {
                        *wclient = Some(client);
                        // drop the write lock before making the request
                        let rclient = RwLockWriteGuard::downgrade(wclient);
                        rclient.as_ref().unwrap().request::<R>(method, params).await
                    }
                    Err(err) => {
                        error!(%err, "unable to connect to server");
                        Err(err)
                    }
                }
            }
        }
    }
}

impl<C: JsonRpcClient> WsFederationApi<C> {
    pub async fn request<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        param: P,
    ) -> Result<R> {
        let params = [serde_json::to_value(param).expect("encoding error")];
        let requests = self
            .members
            .iter()
            .map(|member| Box::pin(member.request(method, &params)));

        let mut error = None;
        let mut successes = 0;
        for request in requests {
            match request.await {
                Ok(res) => {
                    if successes == self.max_evil {
                        return Ok(res);
                    } else {
                        successes += 1;
                    }
                }
                Err(e) => error = Some(e),
            };
        }

        Err(ApiError::RpcError(
            error.expect("If there was no success there has to be an error"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use once_cell::sync::Lazy;
    use std::{
        collections::HashSet,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Mutex,
        },
    };

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

        async fn connect(_url: &str) -> Result<Self> {
            Ok(Self(C::connect().await?))
        }
    }

    #[async_trait]
    impl<C: SimpleClient + Send + Sync> ClientT for Client<C> {
        async fn request<'a, R>(
            &self,
            method: &'a str,
            _params: Option<jsonrpsee_types::ParamsSer<'a>>,
        ) -> Result<R>
        where
            R: jsonrpsee_core::DeserializeOwned,
        {
            let json = self.0.request(method).await?;
            Ok(serde_json::from_str(&json).unwrap())
        }

        async fn notification<'a>(
            &self,
            _method: &'a str,
            _params: Option<jsonrpsee_types::ParamsSer<'a>>,
        ) -> Result<()> {
            unimplemented!()
        }

        async fn batch_request<'a, R>(
            &self,
            _batch: Vec<(&'a str, Option<jsonrpsee_types::ParamsSer<'a>>)>,
        ) -> Result<Vec<R>>
        where
            R: jsonrpsee_core::DeserializeOwned + Default + Clone,
        {
            unimplemented!()
        }
    }

    fn federation_member<C: SimpleClient + Send + Sync>() -> FederationMember<Client<C>> {
        FederationMember {
            url: String::new(),
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

        fed.request::<()>("", &[]).await.unwrap();
        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            1,
            "should connect once after first request"
        );

        fed.request::<()>("", &[]).await.unwrap();
        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            1,
            "should not connect again before disconnect"
        );

        // disconnect
        CONNECTED.store(false, Ordering::SeqCst);

        fed.request::<()>("", &[]).await.unwrap();
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
            fed.request::<()>("", &[]).await.is_err(),
            "connect for client 0 should fail"
        );

        // connect for client 1 should succeed
        fed.request::<()>("", &[]).await.unwrap();

        assert_eq!(
            CONNECTION_COUNT.load(Ordering::SeqCst),
            2,
            "should connect again after error in first connect"
        );

        // force a new connection by disconnecting client 1
        FAIL.lock().unwrap().insert(1);

        // only connect once even for two concurrent requests
        let (reqa, reqb) = tokio::join!(fed.request::<()>("", &[]), fed.request::<()>("", &[]));
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
        let (reqa, reqb) = tokio::join!(fed.request::<()>("", &[]), fed.request::<()>("", &[]));

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
