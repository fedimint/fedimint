use crate::api::{FedResponse, Result};
use crate::ApiError;
use fedimint_api::PeerId;
use fedimint_core::epoch::EpochHistory;
use jsonrpsee_core::Error as JsonRpcError;
use jsonrpsee_types::error::CallError as RpcCallError;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use threshold_crypto::PublicKey;

/// Returns a result from the first responding peer
pub struct TrustAllPeers;

impl<R> QueryStrategy<R> for TrustAllPeers {
    fn process(&mut self, response: FedResponse<R>) -> QueryStep<R> {
        let FedResponse { peer: _, result } = response;
        QueryStep::Finished(result.map_err(ApiError::RpcError))
    }
}

/// Returns first epoch with a valid sig, otherwise wait till f+1 agree
pub struct ValidHistory {
    epoch_pk: PublicKey,
    current: CurrentConsensus<EpochHistory>,
}

impl ValidHistory {
    pub fn new(epoch_pk: PublicKey, max_evil: usize) -> Self {
        Self {
            epoch_pk,
            current: CurrentConsensus::new(max_evil),
        }
    }
}

impl QueryStrategy<EpochHistory> for ValidHistory {
    fn process(&mut self, response: FedResponse<EpochHistory>) -> QueryStep<EpochHistory> {
        let FedResponse { peer, result } = response;
        match result {
            Ok(epoch) if epoch.verify_sig(&self.epoch_pk).is_ok() => QueryStep::Finished(Ok(epoch)),
            result => self.current.process(FedResponse { peer, result }),
        }
    }
}

/// Returns the deduplicated union of f+1 responses
pub struct UnionResponses<R> {
    responses: HashSet<PeerId>,
    results: HashSet<R>,
    current: CurrentConsensus<Vec<R>>,
    max_evil: usize,
}

impl<R> UnionResponses<R> {
    pub fn new(max_evil: usize) -> Self {
        Self {
            responses: HashSet::new(),
            results: HashSet::new(),
            current: CurrentConsensus::new(max_evil),
            max_evil,
        }
    }
}

impl<R: Hash + Eq + Clone> QueryStrategy<Vec<R>> for UnionResponses<R> {
    fn process(&mut self, response: FedResponse<Vec<R>>) -> QueryStep<Vec<R>> {
        if let FedResponse {
            peer,
            result: Ok(result),
        } = response
        {
            self.results.extend(result.into_iter());
            self.responses.insert(peer);

            if self.responses.len() > self.max_evil {
                QueryStep::Finished(Ok(self.results.drain().collect()))
            } else {
                QueryStep::Continue
            }
        } else {
            // handle error case using the CurrentConsensus method
            self.current.process(response)
        }
    }
}

/// Returns when f+1 responses are equal, retrying on 404 errors
pub struct Retry404<R> {
    current: CurrentConsensus<R>,
}

impl<R> Retry404<R> {
    pub fn new(max_evil: usize) -> Self {
        Self {
            current: CurrentConsensus::new(max_evil),
        }
    }
}

impl<R: Hash + Eq + Clone> QueryStrategy<R> for Retry404<R> {
    fn process(&mut self, response: FedResponse<R>) -> QueryStep<R> {
        let FedResponse { peer, result } = response;
        match result {
            Err(JsonRpcError::Call(RpcCallError::Custom(e))) if e.code() == 404 => {
                QueryStep::Request(HashSet::from([peer]))
            }
            result => self.current.process(FedResponse { peer, result }),
        }
    }
}

/// Returns when f+1 responses are equal, retrying after every 2f+1 responses
// FIXME: should be replaced by queries for specific epochs in case we cannot get enough responses
// FIXME: for any single epoch
pub struct EventuallyConsistent<R> {
    responses: HashSet<PeerId>,
    current: CurrentConsensus<R>,
    max_evil: usize,
}

impl<R> EventuallyConsistent<R> {
    pub fn new(max_evil: usize) -> Self {
        Self {
            responses: HashSet::new(),
            current: CurrentConsensus::new(max_evil),
            max_evil,
        }
    }
}

impl<R: Hash + Eq + Clone> QueryStrategy<R> for EventuallyConsistent<R> {
    fn process(&mut self, response: FedResponse<R>) -> QueryStep<R> {
        let honest_threshold = self.max_evil * 2 + 1;
        self.responses.insert(response.peer);

        match self.current.process(response) {
            QueryStep::Continue if self.responses.len() == honest_threshold => {
                let result = QueryStep::Request(self.responses.clone());
                self.responses.clear();
                result
            }
            result => result,
        }
    }
}

/// Returns when f+1 responses are equal
pub struct CurrentConsensus<R> {
    pub results: HashMap<R, HashSet<PeerId>>,
    pub errors: HashMap<PeerId, JsonRpcError>,
    max_evil: usize,
}

impl<R> CurrentConsensus<R> {
    pub fn new(max_evil: usize) -> Self {
        Self {
            results: HashMap::new(),
            errors: HashMap::new(),
            max_evil,
        }
    }
}

impl<R: Hash + Eq + Clone> QueryStrategy<R> for CurrentConsensus<R> {
    fn process(&mut self, response: FedResponse<R>) -> QueryStep<R> {
        match response {
            FedResponse {
                peer,
                result: Ok(result),
            } => {
                let peers = self.results.entry(result).or_insert_with(HashSet::new);
                peers.insert(peer);
            }
            FedResponse {
                peer,
                result: Err(error),
            } => {
                self.errors.insert(peer, error);
            }
        }

        for (result, peers) in self.results.iter() {
            if peers.len() > self.max_evil {
                return QueryStep::Finished(Ok(result.clone()));
            }
        }

        if self.errors.len() > self.max_evil {
            let (_, error) = self.errors.drain().next().expect("non-empty");
            return QueryStep::Finished(Err(ApiError::RpcError(error)));
        }

        QueryStep::Continue
    }
}

pub trait QueryStrategy<R> {
    fn process(&mut self, response: FedResponse<R>) -> QueryStep<R>;
}

/// Results from the strategy handling a response from a peer
///
/// `Request` sending requests to some of the peers
/// `Continue` awaiting and handling responses
/// `Finished` return a final result
pub enum QueryStep<R> {
    Request(HashSet<PeerId>),
    Continue,
    Finished(Result<R>),
}
