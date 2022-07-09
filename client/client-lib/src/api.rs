use async_trait::async_trait;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use futures::StreamExt;
use jsonrpsee_core::client::ClientT;
use jsonrpsee_core::Error as JsonRpcError;
use jsonrpsee_types::error::CallError as RpcCallError;
use minimint_api::{OutPoint, PeerId, TransactionId};
use minimint_core::modules::ln::contracts::incoming::IncomingContractOffer;
use minimint_core::modules::ln::contracts::ContractId;
use minimint_core::modules::ln::ContractAccount;
use minimint_core::outcome::{TransactionStatus, TryIntoOutcome};
use minimint_core::transaction::Transaction;
use minimint_core::CoreError;

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
}

#[derive(Debug, Clone)]
/// Mint API client that will try to run queries against all `members` expecting equal
/// results from at least `min_eq_results` of them. Members that return differing results are
/// returned as a member faults list.
pub struct WsFederationApi<C> {
    clients: Vec<(PeerId, C)>,
    max_evil: usize,
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
impl<C: ClientT + Send + Sync> FederationApi for WsFederationApi<C> {
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

#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};

#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};

impl WsFederationApi<WsClient> {
    /// Creates a new API client
    pub async fn new(max_evil: usize, members: Vec<(PeerId, String)>) -> Self {
        WsFederationApi {
            clients: futures::stream::iter(members)
                .then(|(peer, url)| async move {
                    // TODO: reconnect to peers on disconnect
                    (
                        peer,
                        WsClientBuilder::default()
                            .build(url)
                            .await
                            .expect("unable to connect to server"),
                    )
                })
                .collect()
                .await,
            max_evil,
        }
    }
}

impl<C: ClientT> WsFederationApi<C> {
    pub async fn request<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        param: P,
    ) -> Result<R> {
        let params = [serde_json::to_value(param).expect("encoding error")];
        let mut requests = futures::stream::iter(&self.clients).then(|(_id, client)| {
            client.request::<R>(method, Some(jsonrpsee_types::ParamsSer::ArrayRef(&params)))
        });

        let mut error = None;
        let mut successes = 0;
        while let Some(result) = requests.next().await {
            match result {
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
