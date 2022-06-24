use async_trait::async_trait;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use futures::{Future, StreamExt, TryFutureExt};
use minimint_api::{OutPoint, PeerId, TransactionId};
use minimint_core::modules::ln::contracts::incoming::IncomingContractOffer;
use minimint_core::modules::ln::contracts::ContractId;
use minimint_core::modules::ln::ContractAccount;
use minimint_core::outcome::{MismatchingVariant, TransactionStatus, TryIntoOutcome};
use minimint_core::transaction::Transaction;
use reqwest::{StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
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
                    .and_then(|output| output.try_into_variant().map_err(ApiError::WrongOutputType))
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
pub struct HttpFederationApi {
    federation_member_api_hosts: Vec<(PeerId, Url)>,
    http_client: reqwest::Client,
}

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("Accepted transaction errored on execution: {0}")]
    TransactionError(String),
    #[error("Out point out of range, transaction got {0} outputs, requested element {1}")]
    OutPointOutOfRange(usize, usize),
    #[error("Returned output type did not match expectation: {0}")]
    WrongOutputType(MismatchingVariant),
    #[error("Timeout error awaiting outcome")]
    Timeout,
}

impl ApiError {
    /// Returns `true` if the error means that the queried coin output isn't ready yet but might
    /// become ready later.
    pub fn is_retryable(&self) -> bool {
        match self {
            ApiError::HttpError(e) => e.status() == Some(StatusCode::NOT_FOUND),
            _ => false,
        }
    }
}

#[cfg(not(target_family = "wasm"))]
type ParHttpFuture<'a, T> = Pin<Box<dyn Future<Output = (PeerId, reqwest::Result<T>)> + Send + 'a>>;

#[cfg(target_family = "wasm")]
type ParHttpFuture<'a, T> = Pin<Box<dyn Future<Output = (PeerId, reqwest::Result<T>)> + 'a>>;

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl FederationApi for HttpFederationApi {
    /// Fetch the outcome of an entire transaction
    async fn fetch_tx_outcome(&self, tx: TransactionId) -> Result<TransactionStatus> {
        self.get(&format!("/transaction/{}", tx)).await
    }

    /// Submit a transaction to all federtion members
    async fn submit_transaction(&self, tx: Transaction) -> Result<TransactionId> {
        // TODO: check the id is correct
        self.put("/transaction", tx).await
    }

    async fn fetch_contract(&self, contract: ContractId) -> Result<ContractAccount> {
        self.get(&format!("/ln/account/{}", contract)).await
    }

    async fn fetch_consensus_block_height(&self) -> Result<u64> {
        self.get("/wallet/block_height").await
    }

    async fn fetch_offer(&self, payment_hash: Sha256Hash) -> Result<IncomingContractOffer> {
        self.get(&format!("/ln/offer/{}", payment_hash)).await
    }
}

impl HttpFederationApi {
    /// Creates a new API client
    pub fn new(members: Vec<(PeerId, Url)>) -> HttpFederationApi {
        HttpFederationApi {
            federation_member_api_hosts: members,
            http_client: Default::default(),
        }
    }

    /// Send a GET request to all federation members and make sure that there is consensus about the
    /// return value between members.
    ///
    /// # Panics
    /// If `api_endpoint` is not a valid relative URL.
    pub async fn get<T>(&self, api_endpoint: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned + Eq + Hash,
    {
        self.parallel_http_op(|http_client, id, base_url| {
            Box::pin(async move {
                let request_url = base_url.join(api_endpoint).expect("Invalid API endpoint");
                let response = http_client
                    .get(request_url)
                    .send()
                    .and_then(|resp| async { resp.error_for_status()?.json().await })
                    .await;
                (id, response)
            })
        })
        .await
    }

    /// Send a PUT request to all federation members and make sure that there is consensus about the
    /// return value between members.
    ///
    /// # Panics
    /// If `api_endpoint` is not a valid relative URL.
    pub async fn put<S, R>(&self, api_endpoint: &str, data: S) -> Result<R>
    where
        S: Serialize + Clone + Send + Sync,
        R: DeserializeOwned + Eq + Hash,
    {
        self.parallel_http_op(|http_client, id, base_url| {
            let cloned_data = data.clone();
            Box::pin(async move {
                let request_url = base_url.join(api_endpoint).expect("Invalid API endpoint");
                let response = http_client
                    .put(request_url)
                    .json(&cloned_data)
                    .send()
                    .and_then(|resp| resp.json())
                    .await;
                (id, response)
            })
        })
        .await
    }

    // TODO: check for consistency of replies, needs epoch-versioned API replies
    /// This function is used to run the same HTTP request against multiple endpoint belonging to
    /// different federation members and returns the first success or if none occurs the last error.
    async fn parallel_http_op<'a, T, F>(&'a self, make_request: F) -> Result<T>
    where
        F: Fn(&'a reqwest::Client, PeerId, &'a Url) -> ParHttpFuture<'a, T>,
        T: serde::de::DeserializeOwned + Eq + Hash,
    {
        let mut requests = futures::stream::iter(self.federation_member_api_hosts.iter())
            .then(|(id, member)| make_request(&self.http_client, *id, member));

        let mut error = None;
        while let Some((_member_id, result)) = requests.next().await {
            match result {
                Ok(res) => return Ok(res),
                Err(e) => error = Some(e),
            };
        }

        Err(ApiError::HttpError(
            error.expect("If there was no success there has to be an error"),
        ))
    }
}

fn result_eq<T: PartialEq>(a: &reqwest::Result<T>, b: &reqwest::Result<T>) -> bool {
    match (a, b) {
        (Ok(a), Ok(b)) => a == b,
        (Err(a), Err(b)) => {
            if a.is_status() && b.is_status() {
                a.status() == b.status()
            } else {
                false
            }
        }
        (_, _) => false,
    }
}

#[derive(Debug)]
struct ResultWrapper<T>(reqwest::Result<T>);

impl<T> PartialEq for ResultWrapper<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        result_eq(&self.0, &other.0)
    }
}

impl<T> Eq for ResultWrapper<T> where T: Eq + PartialEq {}

impl<T> Hash for ResultWrapper<T>
where
    T: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.0 {
            Ok(res) => res.hash(state),
            Err(e) => e.status().hash(state),
        }
    }
}
