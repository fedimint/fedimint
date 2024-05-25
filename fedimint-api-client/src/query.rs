use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::mem;

use anyhow::anyhow;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{maybe_add_send_sync, NumPeers, NumPeersExt, PeerId};

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

/// Returns when we obtain the first valid responses. RPC call errors or
/// invalid responses are not retried.
pub struct FilterMap<R, T> {
    filter_map: Box<maybe_add_send_sync!(dyn Fn(R) -> anyhow::Result<T>)>,
    error_strategy: ErrorStrategy,
}

impl<R, T> FilterMap<R, T> {
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

impl<R, T> QueryStrategy<R, T> for FilterMap<R, T> {
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

/// Returns when we obtain a threshold of valid responses. RPC call errors or
/// invalid responses are not retried.
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

impl<R, T> QueryStrategy<R, BTreeMap<PeerId, T>> for FilterMapThreshold<R, T> {
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

/// Returns when we obtain a threshold of identical responses. Responses are not
/// assumed to be static and may be updated by the peers; on failure to
/// establish consensus with a threshold of responses, we retry the requests.
/// RPC call errors are not retried.
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

impl<R: Eq> QueryStrategy<R> for ThresholdConsensus<R> {
    fn process(&mut self, peer: PeerId, result: PeerResult<R>) -> QueryStep<R> {
        match result {
            Ok(response) => {
                let current_count = self.responses.values().filter(|r| **r == response).count();

                if current_count + 1 >= self.threshold {
                    return QueryStep::Success(response);
                }

                self.responses.insert(peer, response);

                assert!(self.retry.insert(peer));

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
