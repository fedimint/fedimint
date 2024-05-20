use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Debug;
use std::mem;

use anyhow::anyhow;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{maybe_add_send_sync, NumPeers, NumPeersExt, PeerId};
use itertools::Itertools;

use crate::api::{self, PeerError, PeerResult};

/// Fedimint query strategy
///
/// Due to federated security model each Fedimint client API call to the
/// Federation might require a different way to process one or more required
/// responses from the Federation members. This trait abstracts away the details
/// of each specific strategy for the generic client Api code.
pub trait QueryStrategy<IR, OR = IR> {
    fn process(&mut self, peer_id: PeerId, response: api::PeerResult<IR>) -> QueryStep<OR>;
}

/// Results from the strategy handling a response from a peer
///
/// Note that the implementation driving the [`QueryStrategy`] returning
/// [`QueryStep`] is responsible from remembering and collecting errors
/// for each peer.
#[derive(Debug)]
pub enum QueryStep<R> {
    /// Retry request to this peer
    Retry(BTreeSet<PeerId>),
    /// Do nothing yet, keep waiting for requests
    Continue,
    /// Return the successful result
    Success(R),
    /// Fail the whole request
    Failure {
        general: Option<anyhow::Error>,
        peers: BTreeMap<PeerId, PeerError>,
    },
}

struct ErrorStrategy {
    errors: BTreeMap<PeerId, PeerError>,
    threshold: usize,
}

impl ErrorStrategy {
    pub fn new(threshold: usize) -> Self {
        assert!(threshold > 0);

        Self {
            errors: BTreeMap::new(),
            threshold,
        }
    }

    fn format_errors(&self) -> String {
        use std::fmt::Write;
        self.errors
            .iter()
            .fold(String::new(), |mut s, (peer_id, e)| {
                if !s.is_empty() {
                    write!(s, ", ").expect("can't fail");
                }
                write!(s, "peer-{peer_id}: {e}").expect("can't fail");

                s
            })
    }

    pub fn process<R>(&mut self, peer: PeerId, error: PeerError) -> QueryStep<R> {
        assert!(self.errors.insert(peer, error).is_none());

        if self.errors.len() == self.threshold {
            QueryStep::Failure {
                general: Some(anyhow!(
                    "Received errors from {} peers: {}",
                    self.threshold,
                    self.format_errors()
                )),
                peers: mem::take(&mut self.errors),
            }
        } else {
            QueryStep::Continue
        }
    }
}

/// Returns the first valid response. The response of a peer is
/// assumed to be final, hence this query strategy does not implement retry
/// logic.
pub struct FilterMap<R, T> {
    filter_map: Box<maybe_add_send_sync!(dyn Fn(R) -> anyhow::Result<T>)>,
    error_strategy: ErrorStrategy,
}

impl<R, T> FilterMap<R, T> {
    /// Strategy for returning first response that is verifiable (typically with
    /// a signature)
    pub fn new(
        filter_map: impl Fn(R) -> anyhow::Result<T> + MaybeSend + MaybeSync + 'static,
        num_peers: NumPeers,
    ) -> Self {
        Self {
            filter_map: Box::new(filter_map),
            error_strategy: ErrorStrategy::new(num_peers.threshold()),
        }
    }
}

impl<R: Debug + Eq + Clone, T> QueryStrategy<R, T> for FilterMap<R, T> {
    fn process(&mut self, peer: PeerId, result: PeerResult<R>) -> QueryStep<T> {
        match result {
            Ok(response) => match (self.filter_map)(response) {
                Ok(value) => QueryStep::Success(value),
                Err(error) => self
                    .error_strategy
                    .process(peer, PeerError::InvalidResponse(error.to_string())),
            },
            Err(error) => self.error_strategy.process(peer, error),
        }
    }
}

/// Returns when a threshold of valid responses. The response of a peer is
/// assumed to be final, hence this query strategy does not implement retry
/// logic.
pub struct FilterMapThreshold<R, T> {
    filter_map: Box<maybe_add_send_sync!(dyn Fn(PeerId, R) -> anyhow::Result<T>)>,
    error_strategy: ErrorStrategy,
    filtered_responses: BTreeMap<PeerId, T>,
    threshold: usize,
}

impl<R, T> FilterMapThreshold<R, T> {
    pub fn new(
        verifier: impl Fn(PeerId, R) -> anyhow::Result<T> + MaybeSend + MaybeSync + 'static,
        num_peers: NumPeers,
    ) -> Self {
        Self {
            filter_map: Box::new(verifier),
            error_strategy: ErrorStrategy::new(num_peers.one_honest()),
            filtered_responses: BTreeMap::new(),
            threshold: num_peers.threshold(),
        }
    }
}

impl<R: Eq + Clone + Debug, T> QueryStrategy<R, BTreeMap<PeerId, T>> for FilterMapThreshold<R, T> {
    fn process(&mut self, peer: PeerId, result: PeerResult<R>) -> QueryStep<BTreeMap<PeerId, T>> {
        match result {
            Ok(response) => match (self.filter_map)(peer, response) {
                Ok(response) => {
                    self.filtered_responses.insert(peer, response);

                    if self.filtered_responses.len() == self.threshold {
                        QueryStep::Success(mem::take(&mut self.filtered_responses))
                    } else {
                        QueryStep::Continue
                    }
                }
                Err(error) => self
                    .error_strategy
                    .process(peer, PeerError::InvalidResponse(error.to_string())),
            },
            Err(error) => self.error_strategy.process(peer, error),
        }
    }
}

/// Returns when we obtain a threshold of identical responses
pub struct ThresholdConsensus<R> {
    error_strategy: ErrorStrategy,
    responses: BTreeMap<PeerId, R>,
    retry: BTreeSet<PeerId>,
    threshold: usize,
}

impl<R> ThresholdConsensus<R> {
    pub fn new(num_peers: NumPeers) -> Self {
        Self {
            error_strategy: ErrorStrategy::new(num_peers.one_honest()),
            responses: BTreeMap::new(),
            retry: BTreeSet::new(),
            threshold: num_peers.threshold(),
        }
    }
}

impl<R: Eq> ThresholdConsensus<R> {
    /// Get the most common response that has been processed so far. If there is
    /// a tie between two values, the value picked is arbitrary and stability
    /// between calls is not guaranteed.
    fn get_most_common_response(&self) -> Option<&R> {
        // TODO: This implementation scales poorly as `self.responses` increases (n^2)
        self.responses
            .values()
            .max_by_key(|response| self.responses.values().filter(|r| r == response).count())
    }
}

impl<R: Eq + Clone + Debug> QueryStrategy<R> for ThresholdConsensus<R> {
    fn process(&mut self, peer: PeerId, result: api::PeerResult<R>) -> QueryStep<R> {
        match result {
            Ok(response) => {
                self.responses.insert(peer, response);
                assert!(self.retry.insert(peer));

                if let Some(most_common_response) = self.get_most_common_response() {
                    let count = self
                        .responses
                        .values()
                        .filter(|r| r == &most_common_response)
                        .count();

                    if count >= self.threshold {
                        return QueryStep::Success(most_common_response.clone());
                    }
                }

                if self.retry.len() == self.threshold {
                    QueryStep::Retry(mem::take(&mut self.retry))
                } else {
                    QueryStep::Continue
                }
            }
            Err(error) => self.error_strategy.process(peer, error),
        }
    }
}

/// Returns the deduplicated union of a threshold of responses; elements are
/// in descending order by the number of duplications across different peers.
pub struct UnionResponses<R> {
    error_strategy: ErrorStrategy,
    responses: HashMap<PeerId, Vec<R>>,
    threshold: usize,
}

impl<R> UnionResponses<R> {
    pub fn new(num_peers: NumPeers) -> Self {
        Self {
            error_strategy: ErrorStrategy::new(num_peers.one_honest()),
            responses: HashMap::new(),
            threshold: num_peers.threshold(),
        }
    }
}

impl<R: Debug + Eq + Clone> QueryStrategy<Vec<R>> for UnionResponses<R> {
    fn process(&mut self, peer: PeerId, result: PeerResult<Vec<R>>) -> QueryStep<Vec<R>> {
        match result {
            Ok(response) => {
                assert!(self.responses.insert(peer, response).is_none());

                if self.responses.len() == self.threshold {
                    let mut union = self
                        .responses
                        .values()
                        .flatten()
                        .dedup()
                        .cloned()
                        .collect::<Vec<R>>();

                    union.sort_by_cached_key(|r| {
                        self.responses
                            .values()
                            .filter(|response| !response.contains(r))
                            .count()
                    });

                    QueryStep::Success(union)
                } else {
                    QueryStep::Continue
                }
            }
            Err(error) => self.error_strategy.process(peer, error),
        }
    }
}

/// Returns the deduplicated union of `required` number of responses
///
/// Unlike [`UnionResponses`], it works with single values, not `Vec`s.
pub struct UnionResponsesSingle<R> {
    error_strategy: ErrorStrategy,
    responses: HashSet<PeerId>,
    union: Vec<R>,
    threshold: usize,
}

impl<R> UnionResponsesSingle<R> {
    pub fn new(num_peers: NumPeers) -> Self {
        Self {
            error_strategy: ErrorStrategy::new(num_peers.one_honest()),
            responses: HashSet::new(),
            union: vec![],
            threshold: num_peers.threshold(),
        }
    }
}

impl<R: Debug + Eq + Clone> QueryStrategy<R, Vec<R>> for UnionResponsesSingle<R> {
    fn process(&mut self, peer: PeerId, result: PeerResult<R>) -> QueryStep<Vec<R>> {
        match result {
            Ok(response) => {
                if !self.union.contains(&response) {
                    self.union.push(response);
                }

                assert!(self.responses.insert(peer));

                if self.responses.len() == self.threshold {
                    QueryStep::Success(mem::take(&mut self.union))
                } else {
                    QueryStep::Continue
                }
            }
            Err(error) => self.error_strategy.process(peer, error),
        }
    }
}
