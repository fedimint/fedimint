use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Debug;
use std::mem;

use fedimint_core::PeerId;
use jsonrpsee_core::Error as JsonRpcError;
use jsonrpsee_types::error::CallError as RpcCallError;
use tracing::debug;

use crate::api;
use crate::api::MemberError;

/// Returns a result from the first responding peer
pub struct TrustAllPeers;

impl<R> QueryStrategy<R> for TrustAllPeers {
    fn process(&mut self, peer: PeerId, result: api::MemberResult<R>) -> QueryStep<R> {
        match result {
            Ok(o) => QueryStep::Success(o),
            Err(e) => QueryStep::FailMembers(BTreeMap::from([(peer, e)])),
        }
    }
}

/// Returns first response with a valid sig
pub struct VerifiableResponse<R> {
    verifier: Box<dyn Fn(&R) -> bool + Send + Sync>,
    allow_consensus_fallback: bool,
    current: CurrentConsensus<R>,
}

impl<R> VerifiableResponse<R> {
    /// Strategy for returning first response that is verifiable (typically with
    /// a signature)
    ///
    /// * `required`: How many responses until a failure or success is returned
    /// * `allow_consensus_fallback`: Returns a success if cannot verify but
    ///   `required` agree
    /// * `verifier`: Function that verifies the data with the public key
    pub fn new(
        required: usize,
        allow_consensus_fallback: bool,
        verifier: impl Fn(&R) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            verifier: Box::new(verifier),
            allow_consensus_fallback,
            current: CurrentConsensus::new(required),
        }
    }
}

impl<R: Debug + Eq + Clone> QueryStrategy<R> for VerifiableResponse<R> {
    fn process(&mut self, peer: PeerId, result: api::MemberResult<R>) -> QueryStep<R> {
        match result {
            Ok(result) if (self.verifier)(&result) => QueryStep::Success(result),
            Ok(result) => {
                if self.allow_consensus_fallback {
                    self.current.process(peer, Ok(result))
                } else {
                    self.current.process(
                        peer,
                        Err(MemberError::InvalidResponse(
                            "Invalid signature".to_string(),
                        )),
                    )
                }
            }
            error => self.current.process(peer, error),
        }
    }
}

/// Returns the deduplicated union of `required` number of responses
pub struct UnionResponses<R> {
    responses: HashSet<PeerId>,
    existing_results: Vec<R>,
    current: CurrentConsensus<Vec<R>>,
    required: usize,
}

impl<R> UnionResponses<R> {
    pub fn new(required: usize) -> Self {
        Self {
            responses: HashSet::new(),
            existing_results: vec![],
            current: CurrentConsensus::new(required),
            required,
        }
    }
}

impl<R: Debug + Eq + Clone> QueryStrategy<Vec<R>> for UnionResponses<R> {
    fn process(&mut self, peer: PeerId, results: api::MemberResult<Vec<R>>) -> QueryStep<Vec<R>> {
        if let Ok(results) = results {
            for new_result in results {
                if !self.existing_results.iter().any(|r| r == &new_result) {
                    self.existing_results.push(new_result);
                }
            }

            self.responses.insert(peer);

            if self.responses.len() >= self.required {
                QueryStep::Success(mem::take(&mut self.existing_results))
            } else {
                QueryStep::Continue
            }
        } else {
            // handle error case using the CurrentConsensus method
            self.current.process(peer, results)
        }
    }
}

/// Returns the deduplicated union of `required` number of responses
///
/// Unlike [`UnionResponses`], it works with single values, not `Vec`s.
/// TODO: Should we make UnionResponses a wrapper around this one?
pub struct UnionResponsesSingle<R> {
    responses: HashSet<PeerId>,
    existing_results: Vec<R>,
    current: CurrentConsensus<Vec<R>>,
    required: usize,
}

impl<R> UnionResponsesSingle<R> {
    pub fn new(required: usize) -> Self {
        Self {
            responses: HashSet::new(),
            existing_results: vec![],
            current: CurrentConsensus::new(required),
            required,
        }
    }
}

impl<R: Debug + Eq + Clone> QueryStrategy<R, Vec<R>> for UnionResponsesSingle<R> {
    fn process(&mut self, peer: PeerId, result: api::MemberResult<R>) -> QueryStep<Vec<R>> {
        match result {
            Ok(new_result) => {
                if !self.existing_results.iter().any(|r| r == &new_result) {
                    self.existing_results.push(new_result);
                }

                self.responses.insert(peer);

                if self.responses.len() >= self.required {
                    QueryStep::Success(mem::take(&mut self.existing_results))
                } else {
                    QueryStep::Continue
                }
            }
            Err(e) => {
                // handle error case using the CurrentConsensus method
                self.current.process(peer, Err(e))
            }
        }
    }
}

/// Returns when `required` responses are equal, retrying on 404 errors
pub struct Retry404<R> {
    current: CurrentConsensus<R>,
}

impl<R> Retry404<R> {
    pub fn new(required: usize) -> Self {
        Self {
            current: CurrentConsensus::new(required),
        }
    }
}

impl<R: Debug + Eq + Clone> QueryStrategy<R> for Retry404<R> {
    fn process(&mut self, peer: PeerId, result: api::MemberResult<R>) -> QueryStep<R> {
        match result {
            Err(MemberError::Rpc(JsonRpcError::Call(RpcCallError::Custom(e))))
                if e.code() == 404 =>
            {
                QueryStep::RetryMembers(BTreeSet::from([peer]))
            }
            result => self.current.process(peer, result),
        }
    }
}

/// Returns when `required` responses are equal, retrying after every `required`
/// responses
// FIXME: should be replaced by queries for specific epochs in case we cannot
// get enough responses FIXME: for any single epoch
pub struct EventuallyConsistent<R> {
    responses: BTreeSet<PeerId>,
    current: CurrentConsensus<R>,
    required: usize,
}

impl<R> EventuallyConsistent<R> {
    pub fn new(required: usize) -> Self {
        Self {
            responses: BTreeSet::new(),
            current: CurrentConsensus::new(required),
            required,
        }
    }
}

impl<R: Eq + Clone + Debug> QueryStrategy<R> for EventuallyConsistent<R> {
    fn process(&mut self, peer: PeerId, result: api::MemberResult<R>) -> QueryStep<R> {
        self.responses.insert(peer);

        match self.current.process(peer, result) {
            QueryStep::Continue if self.responses.len() >= self.required => {
                let result = QueryStep::RetryMembers(self.responses.clone());
                self.responses.clear();
                result
            }
            result => result,
        }
    }
}

/// Returns when `required` responses are equal
pub struct CurrentConsensus<R> {
    /// Previously received responses/results
    ///
    /// Since we don't expect a lot of different responses,
    /// it's easier to store them in `Vec` and do a linear search
    /// than required `R: Ord` or `R: Hash`.
    pub existing_results: Vec<(R, HashSet<PeerId>)>,
    pub errors: BTreeMap<PeerId, MemberError>,
    required: usize,
}

impl<R> CurrentConsensus<R> {
    pub fn new(required: usize) -> Self {
        Self {
            existing_results: vec![],
            errors: BTreeMap::new(),
            required,
        }
    }
}

impl<R: Eq + Clone + Debug> QueryStrategy<R> for CurrentConsensus<R> {
    fn process(&mut self, peer: PeerId, result: api::MemberResult<R>) -> QueryStep<R> {
        match result {
            Ok(result) => {
                if let Some((prev_result, peers)) = self
                    .existing_results
                    .iter_mut()
                    .find(|(prev_result, _)| prev_result == &result)
                {
                    if peers.contains(&peer) {
                        debug!(prev = ?prev_result, new = ?result, peer = %peer, "Ignoring duplicate response from peer");
                    } else {
                        peers.insert(peer);
                    }
                } else {
                    self.existing_results.push((result, HashSet::from([peer])));
                }
            }
            Err(error) => {
                self.errors.insert(peer, error);
            }
        }

        for (result, peers) in &self.existing_results {
            if peers.len() >= self.required {
                return QueryStep::Success(result.clone());
            }
        }

        if self.errors.len() >= self.required {
            return QueryStep::Failure(mem::take(&mut self.errors));
        }

        QueryStep::Continue
    }
}

pub trait QueryStrategy<IR, OR = IR> {
    fn process(&mut self, peer_id: PeerId, response: api::MemberResult<IR>) -> QueryStep<OR>;
}

/// Results from the strategy handling a response from a peer
///
/// Note that the implementation driving the [`QueryStrategy`] returning
/// [`QueryStep`] is responsible from remembering and collecting errors
/// for each peer.
#[derive(Debug)]
pub enum QueryStep<R> {
    /// Retry request to this peer
    RetryMembers(BTreeSet<PeerId>),
    /// Fail these members and remember their errors
    FailMembers(BTreeMap<PeerId, MemberError>),
    /// Do nothing yet, keep waiting for requests
    Continue,
    /// Return the succsessful result
    Success(R),
    /// Fail the whole request and remember errors from given members
    Failure(BTreeMap<PeerId, MemberError>),
}
