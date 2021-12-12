use futures::{Future, StreamExt, TryFutureExt};
use minimint::outcome::{MismatchingVariant, TransactionStatus, TryIntoOutcome};
use minimint::transaction::Transaction;
use minimint_api::{OutPoint, PeerId, TransactionId};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use thiserror::Error;

#[derive(Debug)]
/// Mint API client that will try to run queries against all `members` expecting equal
/// results from at least `min_eq_results` of them. Members that return differing results are
/// returned as a member faults list.
pub struct MintApi {
    federation_member_api_hosts: Vec<(PeerId, Url)>,
    http_client: reqwest::Client,
}

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("HTTP error: {0}")]
    HttpError(reqwest::Error),
    #[error("Accepted transaction errored on execution: {0}")]
    TransactionError(String),
    #[error("Out point out of range, transaction got {0} outputs, requested element {1}")]
    OutPointOutOfRange(usize, usize),
    #[error("Returned output type did not match expectation: {0}")]
    WrongOutputType(MismatchingVariant),
}

type ParHttpFuture<'a, T> = Pin<Box<dyn Future<Output = (PeerId, reqwest::Result<T>)> + Send + 'a>>;

impl MintApi {
    /// Creates a new API client
    pub fn new(members: Vec<(PeerId, Url)>) -> MintApi {
        MintApi {
            federation_member_api_hosts: members,
            http_client: Default::default(),
        }
    }

    /// Fetch the outcome of an entire transaction
    pub async fn fetch_tx_outcome(&self, tx: TransactionId) -> Result<TransactionStatus> {
        self.get(&format!("/transaction/{}", tx)).await
    }

    /// Fetch the outcome of a single transaction output
    pub async fn fetch_output_outcome<T>(&self, out_point: OutPoint) -> Result<T>
    where
        T: TryIntoOutcome,
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

    /// Submit a transaction to all federtion members
    pub async fn submit_transaction(&self, tx: Transaction) -> Result<TransactionId> {
        self.put("/transaction", tx).await
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

impl From<reqwest::Error> for ApiError {
    fn from(e: reqwest::Error) -> Self {
        ApiError::HttpError(e)
    }
}
